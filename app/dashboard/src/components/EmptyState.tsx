interface Props {
  title: string;
  body: string;
}

export function EmptyState({ title, body }: Props) {
  return (
    <div className="empty-state">
      <h3>{title}</h3>
      <p>{body}</p>
    </div>
  );
}
