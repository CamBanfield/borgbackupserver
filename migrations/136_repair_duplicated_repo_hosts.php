<?php
/**
 * Migration 136: repair repo paths with a duplicated server host (#513)
 *
 * Before server host validation, a host saved with a scheme such as
 * "https://backup.example.com" made the next host change leave
 * "//backup.example.com" behind in each local repo path, e.g.
 * "ssh://bbs-x@10.0.0.5//backup.example.com///mnt/backups/3/x".
 * Rewrite those paths with the client's current host. Paths whose host
 * part has no slash are left alone.
 */

use BBS\Services\SshKeyManager;

$row = $db->fetchOne("SELECT `value` FROM settings WHERE `key` = 'server_host'");
$globalHost = trim((string) ($row['value'] ?? ''));

$repos = $db->fetchAll(
    "SELECT r.id, r.path, a.server_host_override
     FROM repositories r JOIN agents a ON a.id = r.agent_id
     WHERE r.storage_type = 'local' AND r.path LIKE 'ssh://%'"
);

$fixed = 0;
foreach ($repos as $repo) {
    if (!preg_match('#^ssh://[^@/]+@(.+?)(?:/\./|///)#s', $repo['path'], $m) || !str_contains($m[1], '/')) {
        continue;
    }
    $host = SshKeyManager::stripHostPort(trim((string) ($repo['server_host_override'] ?: $globalHost)));
    if ($host === '' || str_contains($host, '/')) {
        continue;
    }
    $newPath = SshKeyManager::replaceRepoPathHost($repo['path'], $host);
    if ($newPath !== null && $newPath !== $repo['path']) {
        $db->update('repositories', ['path' => $newPath], 'id = ?', [$repo['id']]);
        $fixed++;
    }
}

if ($fixed > 0) {
    $db->insert('server_log', [
        'level' => 'info',
        'message' => "Repaired {$fixed} repository path(s) that had the server host twice",
    ]);
    echo "  Repaired {$fixed} repository path(s) with a duplicated server host.\n";
}
