import { useNavigate } from "../appRouter";

const SetPasswordScreen = () => {
  const navigate = useNavigate();

  return (
    <div style={{ display: "grid", placeItems: "center", minHeight: "100vh" }}>
      <div style={{ textAlign: "center" }}>
        <h1>Set Password</h1>
        <p>Initial password setup placeholder.</p>
        <button type="button" onClick={() => navigate("/unlock")}>
          Continue to Unlock
        </button>
      </div>
    </div>
  );
};

export default SetPasswordScreen;
