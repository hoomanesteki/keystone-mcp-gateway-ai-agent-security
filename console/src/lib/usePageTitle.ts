import { useEffect } from "react";

const SITE = "Keystone console";

/** The tab's title, so a person who has several tabs open can tell this one, and a screen reader
 * says where the person is after a page change. */
export function usePageTitle(title: string): void {
  useEffect(() => {
    document.title = `${title} - ${SITE}`;
    return () => {
      document.title = SITE;
    };
  }, [title]);
}
