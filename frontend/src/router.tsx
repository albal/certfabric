import { QueryCache, QueryClient } from "@tanstack/react-query";
import {
  Link,
  Outlet,
  createRootRouteWithContext,
  createRoute,
  createRouter,
  redirect,
  useRouter,
} from "@tanstack/react-router";

import { api, AuthRequired, type AuthStatus } from "./api";
import { HealthRibbon } from "./components/HealthRibbon";
import { FleetPage } from "./pages/Fleet";
import { LoginPage } from "./pages/Login";

export const queryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (error) => {
      // The session expired mid-use: back to the login page.
      if (error instanceof AuthRequired) window.location.assign("/login");
    },
  }),
  defaultOptions: { queries: { retry: (count, error) => !(error instanceof AuthRequired) && count < 2 } },
});

const authStatus = () =>
  queryClient.fetchQuery({ queryKey: ["auth"], queryFn: () => api.get<AuthStatus>("/api/auth/status"), staleTime: 0 });

const rootRoute = createRootRouteWithContext<{ queryClient: QueryClient }>()({ component: Outlet });

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  loader: authStatus,
  component: function Login() {
    const status = loginRoute.useLoaderData();
    return <LoginPage setupRequired={status.setup_required} />;
  },
});

const NAV = [{ to: "/", label: "Device Fleet" }] as const;

function Shell() {
  const router = useRouter();
  async function logout() {
    await api.post("/api/auth/logout");
    queryClient.clear();
    await router.navigate({ to: "/login" });
  }
  return (
    <div className="flex min-h-screen">
      <aside className="flex w-56 shrink-0 flex-col bg-slate-900 text-white">
        <div className="border-b border-slate-700 px-5 py-4 text-lg font-bold tracking-tight">
          Cert<span className="text-blue-500">Fabric</span>
        </div>
        <nav className="flex flex-1 flex-col gap-1 p-3 text-sm">
          {NAV.map((item) => (
            <Link
              key={item.to}
              to={item.to}
              className="rounded px-3 py-2 hover:bg-slate-800"
              activeProps={{ className: "bg-slate-800 border-l-4 border-blue-600 font-semibold" }}
            >
              {item.label}
            </Link>
          ))}
        </nav>
        <button onClick={logout} className="m-3 rounded border border-slate-600 px-3 py-2 text-sm hover:bg-slate-800">
          Sign out
        </button>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <HealthRibbon />
        <main className="flex-1">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

const appRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "app",
  beforeLoad: async () => {
    const status = await authStatus();
    if (!status.authenticated) throw redirect({ to: "/login" });
  },
  component: Shell,
});

const fleetRoute = createRoute({ getParentRoute: () => appRoute, path: "/", component: FleetPage });

const routeTree = rootRoute.addChildren([loginRoute, appRoute.addChildren([fleetRoute])]);

export const router = createRouter({ routeTree, context: { queryClient } });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
