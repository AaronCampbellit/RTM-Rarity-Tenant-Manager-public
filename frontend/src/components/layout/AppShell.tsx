import { useEffect, useRef, useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { Header } from "./Header";
import { WhatIfModal } from "@/components/modals/WhatIfModal";
import { SaveWorkingSetModal } from "@/components/modals/SaveWorkingSetModal";
import { RouteErrorBoundary } from "@/components/common/RouteErrorBoundary";

export function AppShell() {
  const { pathname } = useLocation();
  const contentRef = useRef<HTMLDivElement>(null);
  const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false);

  // Content scrolls to top on navigation (Interactions & Behavior → Routing).
  useEffect(() => {
    contentRef.current?.scrollTo(0, 0);
    setMobileNavigationOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (!mobileNavigationOpen) return;

    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMobileNavigationOpen(false);
    };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [mobileNavigationOpen]);

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar className="hidden md:flex" />
      {mobileNavigationOpen && (
        <div className="fixed inset-0 z-50 md:hidden">
          <button
            type="button"
            aria-label="Close navigation"
            className="absolute inset-0 bg-black/60"
            onClick={() => setMobileNavigationOpen(false)}
          />
          <div
            id="mobile-navigation"
            role="dialog"
            aria-modal="true"
            aria-label="Main navigation"
            className="relative h-full w-[min(86vw,320px)] animate-[drawer-in_.2s_ease-out]"
          >
            <Sidebar
              className="w-full"
              onClose={() => setMobileNavigationOpen(false)}
            />
          </div>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <Header
          mobileNavigationOpen={mobileNavigationOpen}
          onOpenNavigation={() => setMobileNavigationOpen(true)}
        />
        <main
          ref={contentRef}
          className="flex-1 overflow-x-hidden overflow-y-auto px-4 py-4 sm:px-6 sm:py-[22px]"
        >
          <div key={pathname} className="animate-fade">
            <RouteErrorBoundary><Outlet /></RouteErrorBoundary>
          </div>
        </main>
      </div>

      {/* Global write-gate modals */}
      <WhatIfModal />
      <SaveWorkingSetModal />
    </div>
  );
}
