#!/usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const commander_1 = require("commander");
const detector_1 = require("./detector");
const program = new commander_1.Command();
program
    .name('node-pkg-scanner')
    .description('Detect compromised packages (from the Shai Hulud supply chain attack)')
    .version('1.0.0');
program
    .command('scan')
    .description('Scan for compromised packages')
    .option('-c, --config <path>', 'Path to config file', '.config.yml')
    .option('-d, --directory <path>', 'Root directory to scan', process.cwd())
    .option('--no-fail', 'Do not exit with error code when compromised packages found')
    .option('--quiet', 'Suppress non-essential output')
    .option('--silent', 'Suppress all output (for preinstall hooks)')
    .action(async (options) => {
    try {
        if (!options.quiet) {
            console.log('🛡️  Node Package Scanner - CLI Tool');
            console.log('   Scanning for compromised packages from supply chain attack\n');
        }
        const detector = new detector_1.NodePackageScanner(options.config);
        const summary = await detector.scan(options.directory);
        if (!options.quiet) {
            console.log('\n✅ Scan completed successfully');
        }
        // Exit with error code if compromised packages found and fail is enabled
        if (options.fail !== false && summary.compromisedPackages.length > 0) {
            process.exit(1);
        }
        // Explicitly exit with success code
        process.exit(0);
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error('❌ Scan failed:', message);
        process.exit(1);
    }
});
program
    .command('init')
    .description('Initialize a configuration file')
    .option('-f, --force', 'Overwrite existing config file')
    .action((options) => {
    const fs = require('fs');
    const configPath = '.config.yml';
    if (fs.existsSync(configPath) && !options.force) {
        console.error(`❌ Config file already exists at ${configPath}`);
        console.log('Use --force to overwrite');
        process.exit(1);
    }
    const defaultConfig = `# Node Package Scanner Configuration
# Severity level for compromised packages (error, warning, info)
severityLevel: error

# URL to fetch the compromised packages list from
compromisedPackagesUrl: https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt

# Root directory to scan (optional - defaults to current directory)
# rootDirectory: ./src

# Additional packages to check for (beyond the remote list)
additionalPackages: []
  # - suspicious-package-name

# Directories to exclude from scanning
excludeDirectories:
  - node_modules
  - .git
  - dist
  - build

# Cache timeout in minutes
cacheTimeout: 60
`;
    try {
        fs.writeFileSync(configPath, defaultConfig);
        console.log(`✅ Created config file: ${configPath}`);
        process.exit(0);
    }
    catch (error) {
        console.error(`❌ Failed to create config file: ${error}`);
        process.exit(1);
    }
});
program.parse();
// If no command is provided, show help
if (!process.argv.slice(2).length) {
    program.outputHelp();
}
