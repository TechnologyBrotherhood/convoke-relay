// What clients say about each agent Convoke integrates with. Unknown agents get their id.

const NAMES: Record<string, string> = { claude: 'Claude', omp: 'oh-my-pi', codex: 'Codex' }
const COMMANDS: Record<string, { app: string; menu: string; restart: string }> = {
  claude: { app: 'Claude Code', menu: 'Install Claude Integration', restart: '/exit, then claude --continue' },
  omp: { app: 'oh-my-pi', menu: 'Install oh-my-pi Integration', restart: '/exit, then omp --continue' },
  codex: { app: 'Codex', menu: 'Install Codex Integration', restart: '/quit, then codex resume --last --no-daemon' }
}

/** A short display name, e.g. for a badge or "Message Claude…". */
export function agentName(agent: string | undefined): string {
  return (agent && NAMES[agent]) || agent || 'the agent'
}

/** Why an agent pane shows a raw terminal, and how to fix it. */
export function setupNote(setup: 'install' | 'restart', agent = 'claude'): string {
  const c = COMMANDS[agent] ?? COMMANDS.claude
  return setup === 'install'
    ? `${c.app} is running here without the Convoke integration, so this shows the raw terminal. On the Mac: Remote → ${c.menu}, then restart it (${c.restart}) to see it as a chat.`
    : `This ${c.app} session started before the Convoke integration was installed. Restart it (${c.restart}) to see it as a chat.`
}
