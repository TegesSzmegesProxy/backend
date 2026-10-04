import { describe, expect, it } from 'vitest';
import { planInstall, type Host, type Step } from '../../cli/src/install';

const host = (overrides: Partial<Host> & { installed?: string[] } = {}): Host => {
    const installed = new Set(overrides.installed ?? []);
    return { platform: 'linux', arch: 'x64', isRoot: false, packageManager: 'apt', binDir: '/home/u/.local/bin', has: binary => installed.has(binary), ...overrides };
};
const commands = (steps: Step[]) => steps.flatMap(step => (step.kind === 'command' ? [step.command.join(' ')] : []));
const releases = (steps: Step[]) => steps.flatMap(step => (step.kind === 'release' ? [step.binary] : []));

describe('planInstall', () => {
    it('installs everything on a bare apt host', () => {
        const steps = planInstall(host());
        expect(commands(steps)).toEqual([
            'sudo apt-get update',
            'sudo apt-get install -y nmap lynis redis-server curl unzip',
            'sh -c curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "/home/u/.local/bin"',
            'nuclei -update-templates',
        ]);
        expect(releases(steps)).toEqual(['nuclei', 'httpx']);
    });

    it('only refreshes nuclei templates when everything is present', () => {
        const installed = ['nmap', 'lynis', 'redis-server', 'curl', 'unzip', 'trivy', 'nuclei', 'httpx'];
        expect(planInstall(host({ installed }))).toEqual([
            { kind: 'command', title: 'Update nuclei templates', command: ['nuclei', '-update-templates'], needs: 'nuclei' },
        ]);
    });

    it('skips sudo as root and uses dnf package names', () => {
        const steps = planInstall(host({ isRoot: true, packageManager: 'dnf', installed: ['curl', 'unzip', 'nmap', 'lynis'] }));
        expect(commands(steps)[0]).toBe('dnf install -y redis');
    });

    it('takes every scanner from brew', () => {
        const steps = planInstall(host({ platform: 'darwin', packageManager: 'brew' }));
        expect(commands(steps)[0]).toBe('brew install nmap lynis redis nuclei httpx trivy');
        expect(releases(steps)).toEqual([]);
    });

    it('asks for a manual install of packaged tools without a package manager', () => {
        const steps = planInstall(host({ packageManager: undefined }));
        expect(steps.filter(step => step.kind === 'manual').map(step => step.title)).toEqual([
            'Install nmap with your system package manager',
            'Install lynis with your system package manager',
            'Install redis-server with your system package manager',
        ]);
        expect(releases(steps)).toEqual(['nuclei', 'httpx']);
    });
});
