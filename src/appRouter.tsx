/* eslint-disable react-refresh/only-export-components */
import {
  Children,
  createContext,
  isValidElement,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactElement,
  type ReactNode,
} from "react";

type NavigateOptions = { replace?: boolean };
type RouterContextValue = {
  pathname: string;
  navigate: (to: string, options?: NavigateOptions) => void;
};

const RouterContext = createContext<RouterContextValue | null>(null);

const normalizePath = (value: string) => {
  const path = value.split(/[?#]/, 1)[0] || "/";
  return path.startsWith("/") ? path : `/${path}`;
};

const createRouter = (mode: "browser" | "hash") =>
  function Router({ children }: { children: ReactNode }) {
    const readPath = useCallback(
      () =>
        mode === "hash"
          ? normalizePath(globalThis.location?.hash.replace(/^#/, "") || "/")
          : normalizePath(globalThis.location?.pathname || "/"),
      []
    );
    const [pathname, setPathname] = useState(readPath);

    useEffect(() => {
      const eventName = mode === "hash" ? "hashchange" : "popstate";
      const update = () => setPathname(readPath());
      globalThis.addEventListener(eventName, update);
      return () => globalThis.removeEventListener(eventName, update);
    }, [readPath]);

    const navigate = useCallback(
      (to: string, options?: NavigateOptions) => {
        const next = normalizePath(to);
        if (mode === "hash") {
          const hash = `#${next}`;
          if (options?.replace) globalThis.location?.replace(hash);
          else globalThis.location.hash = hash;
          setPathname(next);
          return;
        }
        if (options?.replace) globalThis.history?.replaceState(null, "", next);
        else globalThis.history?.pushState(null, "", next);
        setPathname(next);
      },
      []
    );

    const value = useMemo(() => ({ pathname, navigate }), [navigate, pathname]);
    return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>;
  };

export const BrowserRouter = createRouter("browser");
export const HashRouter = createRouter("hash");

const useRouter = () => {
  const context = useContext(RouterContext);
  if (!context) throw new Error("Router is unavailable");
  return context;
};

export const useLocation = () => {
  const { pathname } = useRouter();
  return { pathname };
};

export const useNavigate = () => useRouter().navigate;

type RouteProps = {
  path: string;
  element: ReactNode;
};

export const Route = (props: RouteProps) => {
  void props;
  return null;
};

const matchesPath = (pattern: string, pathname: string) => {
  if (pattern === "/*" || pattern === "*") return true;
  if (pattern.endsWith("/*")) {
    const prefix = pattern.slice(0, -2);
    return pathname === prefix || pathname.startsWith(`${prefix}/`);
  }
  return normalizePath(pattern) === normalizePath(pathname);
};

export const Routes = ({ children }: { children: ReactNode }) => {
  const { pathname } = useRouter();
  const routes = Children.toArray(children).filter(
    (child): child is ReactElement<RouteProps> => isValidElement<RouteProps>(child)
  );
  return routes.find((route) => matchesPath(route.props.path, pathname))?.props.element ?? null;
};

export const Navigate = ({ to, replace = false }: { to: string; replace?: boolean }) => {
  const navigate = useNavigate();
  useEffect(() => {
    navigate(to, { replace });
  }, [navigate, replace, to]);
  return null;
};
