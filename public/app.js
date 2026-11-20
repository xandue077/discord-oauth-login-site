const notice = document.getElementById("notice");

function showNotice(text, kind) {
  notice.textContent = text;
  notice.className = `notice ${kind}`;
}

const params = new URLSearchParams(window.location.search);

if (params.get("ok") === "1") {
  const name = params.get("name") || params.get("user") || "your account";
  const guild = params.get("guild") || "the server";
  showNotice(`${name} joined server ${guild}.`, "good");
} else if (params.get("error")) {
  showNotice(`Discord login or join failed: ${params.get("error")}`, "bad");
}
