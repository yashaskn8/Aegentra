import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import CasesPanel from "./CasesPanel";

type User = {
  identity_id: string;
  org_id: string;
  role: string;
  csrf_token: string;
};

type Asset = {
  id: string;
  slug: string;
  criticality: string;
};

type Session =
  | { state: "checking" | "unconfigured" | "signed-out" | "error" }
  | { state: "authenticated"; user: User };

async function getSession(signal: AbortSignal): Promise<Session> {
  const response = await fetch("/v1/me", { credentials: "same-origin", cache: "no-store", signal });
  if (response.status === 404) return { state: "unconfigured" };
  if (response.status === 401) return { state: "signed-out" };
  if (!response.ok) return { state: "error" };
  const value: unknown = await response.json();
  if (
    !value || typeof value !== "object" ||
    !("csrf_token" in value) || typeof value.csrf_token !== "string" ||
    !("role" in value) || typeof value.role !== "string" ||
    !("org_id" in value) || typeof value.org_id !== "string" ||
    !("identity_id" in value) || typeof value.identity_id !== "string"
  ) {
    return { state: "error" };
  }
  return { state: "authenticated", user: value as User };
}

export default function AuthPanel() {
  const [session, setSession] = useState<Session>({ state: "checking" });
  const [assets, setAssets] = useState<Asset[]>([]);
  const [assetError, setAssetError] = useState("");
  const [slug, setSlug] = useState("");
  const [criticality, setCriticality] = useState("LOW");
  const [busy, setBusy] = useState(false);
  const [truncated, setTruncated] = useState(false);
  const sessionEpoch = useRef(0);
  const recheckSession = useRef<() => void>(() => {});

  useEffect(() => {
    let active = true;
    let pending: AbortController | null = null;
    const refresh = () => {
      pending?.abort();
      const controller = new AbortController();
      pending = controller;
      sessionEpoch.current += 1;
      // Never display an earlier identity's cached data during reauthorization.
      setSession({ state: "checking" });
      setAssets([]);
      setTruncated(false);
      setAssetError("");
      void getSession(controller.signal)
        .then((result) => {
          if (active && !controller.signal.aborted) setSession(result);
        })
        .catch(() => {
          if (active && !controller.signal.aborted) setSession({ state: "error" });
        });
    };
    const whenVisible = () => {
      if (document.visibilityState === "visible") refresh();
    };
    recheckSession.current = refresh;
    refresh();
    window.addEventListener("focus", refresh);
    window.addEventListener("pageshow", refresh);
    document.addEventListener("visibilitychange", whenVisible);
    return () => {
      active = false;
      pending?.abort();
      recheckSession.current = () => {};
      window.removeEventListener("focus", refresh);
      window.removeEventListener("pageshow", refresh);
      document.removeEventListener("visibilitychange", whenVisible);
    };
  }, []);

  useEffect(() => {
    if (session.state !== "authenticated") return;
    let active = true;
    void fetch("/v1/assets", { credentials: "same-origin", cache: "no-store" })
      .then(async (response) => {
        if (response.status === 401 || response.status === 403) {
          recheckSession.current();
          throw new Error("Asset access changed");
        }
        if (!response.ok) throw new Error("Assets unavailable");
        const data: { items: Asset[]; truncated: boolean } = await response.json();
        if (!Array.isArray(data.items)) throw new Error("Invalid asset response");
        if (active) {
          setAssets(data.items);
          setTruncated(Boolean(data.truncated));
          setAssetError("");
        }
      })
      .catch(() => { if (active) setAssetError("Asset list unavailable."); });
    return () => { active = false; };
  }, [session]);

  async function addAsset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (session.state !== "authenticated" || busy) return;
    setBusy(true);
    setAssetError("");
    const expectedEpoch = sessionEpoch.current;
    try {
      const response = await fetch("/v1/assets", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": session.user.csrf_token,
          "Idempotency-Key": crypto.randomUUID(),
        },
        body: JSON.stringify({ slug, criticality }),
      });
      if (response.status === 401 || response.status === 403) {
        recheckSession.current();
        return;
      }
      if (!response.ok) throw new Error(
        response.status === 409 ? "An asset with this name already exists." : "Could not create asset."
      );
      const created: Asset = await response.json();
      if (expectedEpoch !== sessionEpoch.current) return;
      setAssets((current) => [...current, created].sort((a, b) => a.slug.localeCompare(b.slug)));
      setSlug("");
    } catch (error) {
      if (expectedEpoch === sessionEpoch.current) {
        setAssetError(error instanceof Error ? error.message : "Could not create asset.");
      }
    } finally {
      setBusy(false);
    }
  }

  async function signOut() {
    if (session.state !== "authenticated") return;
    setBusy(true);
    try {
      const response = await fetch("/v1/auth/logout", {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRF-Token": session.user.csrf_token },
      });
      if (!response.ok) throw new Error("Logout failed");
      sessionEpoch.current += 1;
      setAssets([]);
      setTruncated(false);
      setSession({ state: "signed-out" });
    } catch {
      setAssetError("Sign-out failed. Please retry.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="workspace" aria-label="Authenticated workspace">
      <div className="section-heading">
        <h2>Workspace</h2>
        <p>Identity and assets · No release authorization</p>
      </div>
      {session.state === "checking" && <p className="workspace-note">Checking session…</p>}
      {session.state === "unconfigured" && (
        <p className="workspace-note">Authentication is not configured on this backend. No protected data is available.</p>
      )}
      {session.state === "signed-out" && (
        <p className="workspace-note">
          Sign in with an enrolled identity provider to access your assets.{" "}
          <a href="/v1/auth/login">Sign in</a>
        </p>
      )}
      {session.state === "error" && (
        <p className="workspace-note" role="alert">Unable to verify your session right now.</p>
      )}
      {session.state === "authenticated" && (
        <div className="workspace-body">
          <div className="workspace-account">
            <span>Signed in · {session.user.role}</span>
            <button type="button" onClick={() => { void signOut(); }} disabled={busy}>Sign out</button>
          </div>
          <h3>Registered assets</h3>
          {assets.length === 0 && <p className="workspace-note">No assets are currently displayed.</p>}
          <ul className="asset-list">
            {assets.map((asset) => (
              <li key={asset.id}>
                <span>{asset.slug}</span>
                <small>{asset.criticality}</small>
              </li>
            ))}
          </ul>
          {truncated && <p className="workspace-note">Only the first 100 assets are shown.</p>}
          {(session.user.role === "ADMIN" || session.user.role === "EDITOR") && (
            <form onSubmit={(event) => { void addAsset(event); }} className="asset-form">
              <label htmlFor="asset-slug">Asset name</label>
              <input
                id="asset-slug" value={slug} onChange={(event) => setSlug(event.target.value)}
                minLength={3} maxLength={80} pattern="[a-z][a-z0-9-]+"
                required placeholder="web-app" autoComplete="off"
              />
              <label htmlFor="asset-criticality">Criticality</label>
              <select
                id="asset-criticality" value={criticality}
                onChange={(event) => setCriticality(event.target.value)}
              >
                <option value="LOW">Low</option>
                <option value="MEDIUM">Medium</option>
                <option value="HIGH">High</option>
              </select>
              <button disabled={busy} type="submit">{busy ? "Saving…" : "Add asset"}</button>
            </form>
          )}
          {assetError && <p className="workspace-error" role="alert">{assetError}</p>}
          <CasesPanel user={session.user} assets={assets} onAccessLost={() => recheckSession.current()} />
        </div>
      )}
    </section>
  );
}
