import { useNavigate } from "../appRouter";

type UnlockScreenProps = {
  onUnlock: () => void;
  isUnlocked: boolean;
};

const UnlockScreen = ({ onUnlock, isUnlocked }: UnlockScreenProps) => {
  const navigate = useNavigate();

  const handleUnlock = () => {
    onUnlock();
    navigate("/app");
  };

  return (
    <div style={{ display: "grid", placeItems: "center", minHeight: "100vh" }}>
      <div style={{ textAlign: "center" }}>
        <h1>Unlock Vault</h1>
        <p>Vault unlock placeholder.</p>
        <button type="button" onClick={handleUnlock}>
          Unlock
        </button>
        {isUnlocked ? <p>Vault is unlocked.</p> : null}
      </div>
    </div>
  );
};

export default UnlockScreen;
