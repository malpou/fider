interface PoweredByFiderProps {
  slot: string
  className?: string
}

// Removed for our self-hosted instance; kept as a no-op so upstream call
// sites need no changes when rebasing.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const PoweredByFider = (props: PoweredByFiderProps) => {
  return null
}
