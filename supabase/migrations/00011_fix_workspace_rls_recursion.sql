-- Fix two bugs present in the upstream zernio-dev/zernflow schema:
--
-- 1. handle_new_user() ran without an explicit search_path. When triggered
--    by supabase_auth_admin (whose default search_path is just "auth", not
--    "public"), the unqualified inserts into workspaces/workspace_members
--    failed to resolve, and — because this consolidated version of the
--    function has no exception handler — the error propagated up through
--    GoTrue as "Database error creating new user" on every signup.
--
-- 2. The "Owners can manage members" policy on workspace_members did a
--    correlated subquery directly against workspace_members inside its own
--    USING clause (instead of going through a SECURITY DEFINER function like
--    is_workspace_member does). For any role without BYPASSRLS, evaluating
--    that policy re-triggers RLS on workspace_members, which re-evaluates
--    the same policy — infinite recursion. This broke every query that
--    joined through workspace_members (e.g. the dashboard's getWorkspace()),
--    which surfaced as a client-side redirect loop between /login and
--    /dashboard.

create or replace function handle_new_user()
returns trigger as $$
declare
  workspace_id uuid;
  user_name text;
  workspace_slug text;
begin
  user_name := coalesce(
    new.raw_user_meta_data->>'full_name',
    new.raw_user_meta_data->>'name',
    split_part(new.email, '@', 1)
  );
  workspace_slug := lower(regexp_replace(user_name, '[^a-zA-Z0-9]', '-', 'g')) || '-' || substr(new.id::text, 1, 8);

  insert into public.workspaces (name, slug)
  values (user_name || '''s Workspace', workspace_slug)
  returning id into workspace_id;

  insert into public.workspace_members (workspace_id, user_id, role)
  values (workspace_id, new.id, 'owner');

  return new;
exception when others then
  raise log 'handle_new_user error: % %', sqlerrm, sqlstate;
  return new;
end;
$$ language plpgsql security definer set search_path = public;

create or replace function is_workspace_owner(ws_id uuid)
returns boolean as $$
  select exists (
    select 1 from workspace_members
    where workspace_id = ws_id and user_id = auth.uid() and role = 'owner'
  );
$$ language sql security definer stable set search_path = public;

drop policy if exists "Owners can manage members" on workspace_members;

create policy "Owners can manage members" on workspace_members
  using (is_workspace_owner(workspace_id));
