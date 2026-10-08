import * as React from "react";

interface PageContextValue {
  title: string;
  setTitle: (t: string) => void;
}

const PageContext = React.createContext<PageContextValue | null>(null);

export function PageProvider({ children }: { children: React.ReactNode }) {
  const [title, setTitle] = React.useState("Dashboard");
  return (
    <PageContext.Provider value={{ title, setTitle }}>
      {children}
    </PageContext.Provider>
  );
}

export function usePageTitle() {
  const ctx = React.useContext(PageContext);
  if (!ctx) throw new Error("usePageTitle must be used within PageProvider");
  return ctx;
}

/** Set the header title for the lifetime of a screen. */
export function useSetPageTitle(title: string) {
  const { setTitle } = usePageTitle();
  React.useEffect(() => {
    setTitle(title);
  }, [title, setTitle]);
}
