async function renderAppShell(activePage) {
  const mount = document.getElementById("app-nav-mount");
  if (!mount) return;

  let me = { username: "...", role: "student" };
  try { me = await apiFetch("/auth/me"); } catch (e) { /* not logged in */ }

  const initials = (me.username || "??").slice(0, 2).toUpperCase();
  const adminLinkHtml = me.role === "admin"
    ? `<a class="app-nav-link ${activePage === 'admin' ? 'active' : ''}" href="admin.html">${ICONS.admin}<span>Admin</span></a>`
    : "";

  mount.innerHTML = `
    <nav class="app-nav">
      <div class="app-nav-brand">
        <div class="mark">${ICONS.lock}</div>
        <span class="word">Campus<b>Connect</b></span>
      </div>
      <div class="app-nav-links">
        <a class="app-nav-link ${activePage === 'messages' ? 'active' : ''}" href="messages.html">${ICONS.messages}<span>Messages</span></a>
        <a class="app-nav-link ${activePage === 'groups' ? 'active' : ''}" href="groups.html">${ICONS.groups}<span>Study Groups</span></a>
        ${adminLinkHtml}
      </div>
      <div class="app-nav-footer">
        <div class="app-nav-user">
          <div class="avatar">${initials}</div>
          <div class="app-nav-user-info">
            <div class="app-nav-user-name">${me.username}</div>
            <div class="app-nav-user-role">${me.role}</div>
          </div>
        </div>
        <button class="app-nav-logout" id="shell-logout-btn">${ICONS.logout}<span>Log out</span></button>
      </div>
    </nav>
  `;

  document.getElementById("shell-logout-btn").addEventListener("click", () => {
    clearToken();
    sessionStorage.clear();
    window.location.href = "login.html";
  });
}