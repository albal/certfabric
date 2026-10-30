import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";

import { api, ApiError } from "../api";

// First run sets the admin password; afterwards the same page logs in.
export function LoginPage({ setupRequired }: { setupRequired: boolean }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    if (setupRequired && password !== confirm) {
      setError("Passwords do not match");
      return;
    }
    try {
      await api.post(setupRequired ? "/api/auth/setup" : "/api/auth/login", { password });
      await queryClient.invalidateQueries();
      await navigate({ to: "/" });
    } catch (exc) {
      if (exc instanceof ApiError && exc.status === 422) setError("Use at least 12 characters");
      else if (exc instanceof ApiError && exc.status === 401) setError("Wrong password");
      else setError(String(exc));
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-900 p-4">
      <form onSubmit={submit} className="w-full max-w-sm border border-black bg-white p-8" aria-label="Sign in">
        <img src="/favicon.svg" alt="" className="mb-3 h-12 w-12" />
        <h1 className="text-2xl font-bold text-slate-900">CertFabric</h1>
        <p className="mb-6 mt-1 text-sm text-slate-500">
          {setupRequired ? "Set the admin password to finish setup." : "Sign in to manage your certificates."}
        </p>
        <label className="mb-1 block text-sm font-semibold" htmlFor="password">
          {setupRequired ? "New admin password" : "Admin password"}
        </label>
        <input
          id="password"
          type="password"
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="mb-4 w-full border border-black px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-600"
        />
        {setupRequired && (
          <>
            <label className="mb-1 block text-sm font-semibold" htmlFor="confirm">
              Confirm password
            </label>
            <input
              id="confirm"
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className="mb-4 w-full border border-black px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </>
        )}
        {error && (
          <p role="alert" className="mb-4 text-sm font-semibold text-red-600">
            {error}
          </p>
        )}
        <button type="submit" className="w-full bg-blue-600 px-4 py-2 font-semibold text-white hover:bg-blue-700">
          {setupRequired ? "Set password" : "Sign in"}
        </button>
      </form>
    </main>
  );
}
