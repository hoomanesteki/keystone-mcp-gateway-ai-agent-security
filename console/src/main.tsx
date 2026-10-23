import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import { App } from "./app";
import { createOidcAuth } from "./auth/oidc";
import { config } from "./config";
import "./index.css";

const auth = createOidcAuth({
  authority: config.oidcAuthority,
  clientId: config.oidcClientId,
  origin: window.location.origin,
});

const root = document.getElementById("root");
if (!root) throw new Error("index.html has no #root element");

createRoot(root).render(
  <StrictMode>
    <BrowserRouter>
      <App auth={auth} />
    </BrowserRouter>
  </StrictMode>,
);
