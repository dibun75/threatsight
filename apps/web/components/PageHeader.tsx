import Link from "next/link";
import { type ReactNode } from "react";

type Crumb = { href?: string; label: string };

export function PageHeader({
  kicker,
  title,
  lede,
  crumbs,
  actions,
}: {
  kicker: string;
  title: string;
  lede?: string;
  crumbs?: Crumb[];
  actions?: ReactNode;
}) {
  return (
    <header className="page-head">
      {crumbs && crumbs.length > 0 && (
        <nav className="crumbs" aria-label="Breadcrumb">
          {crumbs.map((item, index) => (
            <span key={`${item.label}-${index}`}>
              {index > 0 ? <span aria-hidden="true"> / </span> : null}
              {item.href ? <Link href={item.href}>{item.label}</Link> : <span>{item.label}</span>}
            </span>
          ))}
        </nav>
      )}
      <p className="kicker">{kicker}</p>
      <div className="page-head-row">
        <h1>{title}</h1>
        {actions}
      </div>
      {lede ? <p className="lede">{lede}</p> : null}
    </header>
  );
}
