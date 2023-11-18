import subprocess
import re
import argparse
import textwrap

def is_valid_tag(tag, prefix=None):
    if prefix and not tag.startswith(prefix):
        return False
    return re.match(r'^\d+(\.\d+)*$', tag) is not None

def parse_version(tag):
    return list(map(int, tag.split('.')))

def get_git_tags(repo_path='.', prefix=None):
    tags = subprocess.check_output(['git', 'tag'], cwd=repo_path).decode().splitlines()
    tags = [tag for tag in tags if is_valid_tag(tag, prefix)]
    tags.sort(key=parse_version, reverse=True)
    return tags

def format_log_line_md(line, repo_url=None, repo_name=None):
    first_space_index = line.find(' ')
    if first_space_index == -1:
        first_space_index = 0

    commit_hash = line.split(' ')[0]
    if repo_url and repo_name:
        commit_link = f"[{commit_hash}]({repo_url}/{repo_name}/commit/{commit_hash})"
    else:
        commit_link = commit_hash

    line = commit_link + line[first_space_index:]

    if len(line) > 68:
        indent = '&nbsp;' * (first_space_index + len(commit_hash) + 3)
        wrapped_lines = textwrap.wrap(line, 68 + len(indent), subsequent_indent=indent, break_long_words=False, break_on_hyphens=False)
        return '<br>'.join(wrapped_lines) + '<br>'
    else:
        return line + '<br>'

def format_log_line_txt(line):
    if len(line) > 68:
        first_space_index = line.find(' ')
        if first_space_index == -1:
            first_space_index = 0

        indent = ' ' * (first_space_index + 1)
        wrapped_lines = textwrap.wrap(line, 68, subsequent_indent=indent, break_long_words=False, break_on_hyphens=False)
        return '\n'.join(wrapped_lines)
    else:
        return line

def get_commits_between_tags(tag1, tag2, repo_path='.', formatter=format_log_line_md, **kwargs):
    range = f"{tag1}..{tag2}" if tag1 else tag2
    log_entries = subprocess.check_output(['git', 'log', '--oneline', range], cwd=repo_path).decode().strip().split('\n')
    formatted_entries = [formatter(line, **kwargs) for line in log_entries]
    return '\n'.join(formatted_entries)

def create_changelog_for_repo(repo_path, changelog_file_md, changelog_file_txt, repo_name=None, tag_prefix=None, repo_url=None):
    tags = get_git_tags(repo_path, tag_prefix)
    tags.append('HEAD')
    changelog_file_md.write(f"\n## {repo_name or 'Main Repository'}\n")
    changelog_file_txt.write(f"\n## {repo_name or 'Main Repository'}\n")
    previous_tag = 'HEAD'
    for current_tag in tags:
        title = current_tag if current_tag != 'HEAD' else 'Unreleased Changes'
        changelog_file_md.write(f"\n### {title}\n\n")
        changelog_file_txt.write(f"\n### {title}\n\n")
        commits_md = get_commits_between_tags(current_tag, previous_tag, repo_path, format_log_line_md, repo_url=repo_url, repo_name=repo_name)
        commits_txt = get_commits_between_tags(current_tag, previous_tag, repo_path, format_log_line_txt)
        changelog_file_md.write(commits_md)
        changelog_file_md.write("\n")
        changelog_file_txt.write(commits_txt)
        changelog_file_txt.write("\n")
        previous_tag = current_tag

def create_changelog(tag_prefix=None, repo_url=None, repo_name=None):
    with open('CHANGELOG.md', 'w') as changelog_md, open('CHANGELOG.txt', 'w') as changelog_txt:
        create_changelog_for_repo('.', changelog_md, changelog_txt, tag_prefix=tag_prefix, repo_url=repo_url, repo_name=repo_name)

        submodules = subprocess.check_output(['git', 'submodule', 'foreach', '--quiet', 'echo $path']).decode().splitlines()

        for submodule in submodules:
            submodule_name = submodule.split('/')[-1]  # Assuming submodule path ends with the repo name
            create_changelog_for_repo(submodule, changelog_md, changelog_txt, repo_name=submodule_name, tag_prefix=tag_prefix, repo_url=repo_url)

def main():
    parser = argparse.ArgumentParser(description="Generate a changelog from Git tags and commits.")
    parser.add_argument('--tag-prefix', help="Specify a prefix for the tags to be included in the changelog.")
    parser.add_argument('--repo-url', help="Specify the root URL of the Git repository for commit links.")
    parser.add_argument('--repo-name', help="Specify the name of the Git repository (for the main project).")
    args = parser.parse_args()

    create_changelog(tag_prefix=args.tag_prefix, repo_url=args.repo_url, repo_name=args.repo_name)

if __name__ == "__main__":
    main()
