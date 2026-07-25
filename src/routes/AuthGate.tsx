import { Navigate } from "../appRouter";
import type { ReactNode } from "react";

type AuthGateProps = {
  isUnlocked: boolean;
  children: ReactNode;
};

const AuthGate = ({ isUnlocked, children }: AuthGateProps) => {
  if (!isUnlocked) {
    return <Navigate to="/unlock" replace />;
  }

  return <>{children}</>;
};

export default AuthGate;
