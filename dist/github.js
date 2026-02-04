"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.GitHubIntegration = void 0;
const core = __importStar(require("@actions/core"));
const github = __importStar(require("@actions/github"));
class GitHubIntegration {
    constructor(token) {
        this.COMMENT_MARKER = '<!-- node-package-scanner-comment -->';
        this.context = github.context;
        const finalToken = token || core.getInput('github-token') || process.env.GITHUB_TOKEN || '';
        this.hasValidToken = !!finalToken;
        if (this.hasValidToken) {
            this.octokit = github.getOctokit(finalToken);
        }
    }
    async findExistingComment(prNumber) {
        try {
            const comments = await this.octokit.rest.issues.listComments({
                owner: this.context.repo.owner,
                repo: this.context.repo.repo,
                issue_number: prNumber,
            });
            const existingComment = comments.data.find((comment) => comment.body?.includes(this.COMMENT_MARKER));
            return existingComment?.id ?? null;
        }
        catch (error) {
            console.error("Failed to list PR comments:", error);
            return null;
        }
    }
    async postPRComment(summary) {
        if (!this.hasValidToken) {
            console.log('GitHub token not available, skipping PR comment');
            return;
        }
        if (!this.context.payload.pull_request) {
            console.log('Not running in a pull request context, skipping comment');
            return;
        }
        const prNumber = this.context.payload.pull_request.number;
        const comment = this.generateComment(summary);
        const existingCommentId = await this.findExistingComment(prNumber);
        try {
            // If comment already exists update it
            if (existingCommentId) {
                await this.octokit.rest.issues.updateComment({
                    owner: this.context.repo.owner,
                    repo: this.context.repo.repo,
                    comment_id: existingCommentId,
                    body: comment,
                });
                console.log("✓ Updated existing comment on PR");
                return;
            }
            await this.octokit.rest.issues.createComment({
                owner: this.context.repo.owner,
                repo: this.context.repo.repo,
                issue_number: prNumber,
                body: comment
            });
            console.log('✓ Posted comment to PR');
        }
        catch (error) {
            console.error('Failed to post PR comment:', error);
        }
    }
    generateComment(summary) {
        const { compromisedPackages, scanResults, usingCachedList } = summary;
        let comment = '## 🚨 Compromised Node Package Detection\n\n';
        if (compromisedPackages.length === 0) {
            comment += '✅ **No compromised packages detected**\n\n';
            comment += `Scanned ${summary.totalFiles} package manager files.\n`;
        }
        else {
            comment += `❌ **Found ${compromisedPackages.length} compromised package(s)**\n\n`;
            comment += '### Compromised Packages Found:\n';
            for (const result of scanResults) {
                comment += `\n**${result.file}** (${result.packageManager}):\n`;
                for (const pkg of result.compromisedPackages) {
                    comment += `- \`${pkg.name}\` ⚠️\n`;
                }
            }
            comment += '\n### ⚠️ Action Required\n';
            comment += 'These packages are known to be compromised. ';
            comment += 'Please remove them immediately and review your dependency security.\n\n';
            comment += '**References:**\n';
            comment += '- [Socket.dev Blog: Ongoing Supply Chain Attack](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)\n';
            comment += '- [Compromised Packages List](https://github.com/Cobenian/shai-hulud-detect)\n';
        }
        if (usingCachedList) {
            comment += '\n> ⚠️ **Note:** Using cached compromised packages list (remote fetch failed)\n';
        }
        comment += '\n---\n';
        comment += '*Generated by [Node Package Scanner](https://github.com/drewpayment/node-package-scanner)*';
        return comment;
    }
    setOutputs(summary) {
        if (!this.hasValidToken) {
            console.log('GitHub token not available, skipping GitHub Actions outputs');
            return;
        }
        const hasCompromised = summary.compromisedPackages.length > 0;
        core.setOutput('compromised-found', hasCompromised.toString());
        core.setOutput('compromised-count', summary.compromisedPackages.length.toString());
        core.setOutput('compromised-packages', JSON.stringify(summary.compromisedPackages.map(p => p.name)));
        if (hasCompromised) {
            const severity = core.getInput('fail-on-error') === 'true' ? 'error' : 'warning';
            const message = `Found ${summary.compromisedPackages.length} compromised packages`;
            if (severity === 'error') {
                core.setFailed(message);
            }
            else {
                core.warning(message);
            }
        }
    }
}
exports.GitHubIntegration = GitHubIntegration;
