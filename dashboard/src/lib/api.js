export async function fetchState(signal) {
  const res = await fetch("/api/state", { cache: "no-store", signal });
  if (!res.ok) throw new Error(`state API ${res.status}`);
  return res.json();
}

export async function control(action, scenario) {
  const res = await fetch("/api/control", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, scenario }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`control API ${res.status}: ${body}`);
  }
  return res.json();
}
