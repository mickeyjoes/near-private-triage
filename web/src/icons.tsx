// Inline icons (no icon font, no third-party requests).
import type { ReactElement, SVGProps } from 'react';

type P = SVGProps<SVGSVGElement> & { size?: number };

function base(size: number | undefined, props: SVGProps<SVGSVGElement>, children: ReactElement | ReactElement[]) {
  return (
    <svg width={size ?? 18} height={size ?? 18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>
      {children}
    </svg>
  );
}

export const Shield = ({ size, ...p }: P) => base(size, p, <path d="M12 3l8 3v6c0 4.9-3.4 8.7-8 10-4.6-1.3-8-5.1-8-10V6l8-3z" />);
export const ShieldCheck = ({ size, ...p }: P) =>
  base(size, p, [<path key="a" d="M12 3l8 3v6c0 4.9-3.4 8.7-8 10-4.6-1.3-8-5.1-8-10V6l8-3z" />, <path key="b" d="M8.5 12.2l2.4 2.4 4.6-4.9" />]);
export const ShieldX = ({ size, ...p }: P) =>
  base(size, p, [<path key="a" d="M12 3l8 3v6c0 4.9-3.4 8.7-8 10-4.6-1.3-8-5.1-8-10V6l8-3z" />, <path key="b" d="M9.5 9.5l5 5M14.5 9.5l-5 5" />]);
export const ShieldQ = ({ size, ...p }: P) =>
  base(size, p, [<path key="a" d="M12 3l8 3v6c0 4.9-3.4 8.7-8 10-4.6-1.3-8-5.1-8-10V6l8-3z" />, <path key="b" d="M10 9.6a2.1 2.1 0 1 1 2.9 2c-.6.3-.9.7-.9 1.3v.4M12 16.2v.1" />]);
export const Check = ({ size, ...p }: P) => base(size, p, <path d="M5 12.5l4.2 4.2L19 7" />);
export const X = ({ size, ...p }: P) => base(size, p, <path d="M6 6l12 12M18 6L6 18" />);
export const Question = ({ size, ...p }: P) => base(size, p, [<circle key="a" cx="12" cy="12" r="9" />, <path key="b" d="M9.6 9.4a2.5 2.5 0 1 1 3.5 2.3c-.7.3-1.1.9-1.1 1.6v.3M12 16.8v.1" />]);
export const Lock = ({ size, ...p }: P) => base(size, p, [<rect key="a" x="5" y="10.5" width="14" height="10" rx="2.2" />, <path key="b" d="M8 10.5V8a4 4 0 0 1 8 0v2.5" />]);
export const Key = ({ size, ...p }: P) => base(size, p, [<circle key="a" cx="8" cy="15" r="4" />, <path key="b" d="M11 12l8.5-8.5M16 7l2.5 2.5M14 9l1.8 1.8" />]);
export const Chip = ({ size, ...p }: P) =>
  base(size, p, [<rect key="a" x="6" y="6" width="12" height="12" rx="2" />, <rect key="b" x="9.5" y="9.5" width="5" height="5" rx=".8" />, <path key="c" d="M9 2.5V6M15 2.5V6M9 18v3.5M15 18v3.5M2.5 9H6M2.5 15H6M18 9h3.5M18 15h3.5" />]);
export const Gpu = ({ size, ...p }: P) =>
  base(size, p, [<rect key="a" x="2.5" y="7" width="19" height="10" rx="2" />, <circle key="b" cx="9" cy="12" r="2.6" />, <circle key="c" cx="16" cy="12" r="2.6" />, <path key="d" d="M5 17v3M19 17v3" />]);
export const Dice = ({ size, ...p }: P) =>
  base(size, p, [<rect key="a" x="4" y="4" width="16" height="16" rx="3" />, <circle key="b" cx="9" cy="9" r=".9" fill="currentColor" />, <circle key="c" cx="15" cy="15" r=".9" fill="currentColor" />, <circle key="d" cx="15" cy="9" r=".9" fill="currentColor" />, <circle key="e" cx="9" cy="15" r=".9" fill="currentColor" />]);
export const Gate = ({ size, ...p }: P) => base(size, p, [<path key="a" d="M4 21V5M20 21V5M4 9h16M4 15h16" />, <path key="b" d="M9 9v6M15 9v6" />]);
export const Spark = ({ size, ...p }: P) => base(size, p, <path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M18.4 5.6l-2.8 2.8M8.4 15.6l-2.8 2.8" />);
export const Signature = ({ size, ...p }: P) => base(size, p, [<path key="a" d="M3 17c3-5 5-9 6.5-9 2 0-1.5 9 .5 9 1.3 0 2.2-3 3.5-3s1 2.5 2.5 2.5c1 0 2-1 3-2" />, <path key="b" d="M3 21h18" />]);
export const Download = ({ size, ...p }: P) => base(size, p, [<path key="a" d="M12 4v11M7.5 10.5L12 15l4.5-4.5" />, <path key="b" d="M4.5 19.5h15" />]);
export const File = ({ size, ...p }: P) => base(size, p, [<path key="a" d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5z" />, <path key="b" d="M14 3v5h5M9 13h6M9 17h4" />]);
export const Play = ({ size, ...p }: P) => base(size, p, <path d="M7 5.5v13l11-6.5-11-6.5z" />);
export const Alert = ({ size, ...p }: P) => base(size, p, [<path key="a" d="M12 3.5L2.5 20h19L12 3.5z" />, <path key="b" d="M12 10v4.5M12 17.4v.1" />]);
export const Eye = ({ size, ...p }: P) => base(size, p, [<path key="a" d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z" />, <circle key="b" cx="12" cy="12" r="2.8" />]);
export const Ban = ({ size, ...p }: P) => base(size, p, [<circle key="a" cx="12" cy="12" r="9" />, <path key="b" d="M5.6 5.6l12.8 12.8" />]);
export const Terminal = ({ size, ...p }: P) => base(size, p, [<rect key="a" x="3" y="4.5" width="18" height="15" rx="2.2" />, <path key="b" d="M7 9.5l3 2.5-3 2.5M12.5 15h4.5" />]);
export const Arrow = ({ size, ...p }: P) => base(size, p, <path d="M5 12h14M13 6l6 6-6 6" />);
export const Copy = ({ size, ...p }: P) => base(size, p, [<rect key="a" x="8.5" y="8.5" width="12" height="12" rx="2" />, <path key="b" d="M15.5 8.5V5.5a2 2 0 0 0-2-2h-8a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h3" />]);
export const Chevron = ({ size, ...p }: P) => base(size, p, <path d="M9 6l6 6-6 6" />);
export const Server = ({ size, ...p }: P) =>
  base(size, p, [<rect key="a" x="3.5" y="4" width="17" height="7" rx="1.8" />, <rect key="b" x="3.5" y="13" width="17" height="7" rx="1.8" />, <path key="c" d="M7 7.5h.1M7 16.5h.1" />]);
export const Browser = ({ size, ...p }: P) => base(size, p, [<rect key="a" x="3" y="4" width="18" height="16" rx="2.2" />, <path key="b" d="M3 8.5h18M6 6.3h.1M8.3 6.3h.1" />]);
export const Clock = ({ size, ...p }: P) => base(size, p, [<circle key="a" cx="12" cy="12" r="9" />, <path key="b" d="M12 7v5l3 2" />]);
