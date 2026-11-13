export function MilestoneNotice({
  title,
  milestone,
  children,
}: {
  title: string;
  milestone: string;
  children: string;
}) {
  return (
    <>
      <p className="kicker">{milestone}</p>
      <h1>{title}</h1>
      <div className="notice">
        <strong>Not in M0.</strong>
        <p>{children}</p>
      </div>
    </>
  );
}
