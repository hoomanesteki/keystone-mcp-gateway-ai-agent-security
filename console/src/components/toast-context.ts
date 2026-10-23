import { createContext, useContext } from "react";

export interface ToastInput {
  tone: "success" | "error" | "info";
  title: string;
  detail?: string;
}

export interface Toasts {
  push: (toast: ToastInput) => void;
}

export const ToastContext = createContext<Toasts | null>(null);

export function useToast(): Toasts {
  const toasts = useContext(ToastContext);
  if (!toasts) throw new Error("useToast needs a ToastProvider above it");
  return toasts;
}
