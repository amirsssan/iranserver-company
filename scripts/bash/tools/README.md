# Tools

## mobaxterm_sessions_gen.sh

Generates a **MobaXterm sessions file** (`.mxtsessions`) from a plain list of server names, so hundreds of bookmarks can be imported at once.

> This file was previously named `mobaxterm_random.py`, but it is a Bash script, so it was renamed.

### How it works

- Reads server names from `servers.txt` in the current directory (one per line; blank lines and CRLF are handled).
- Creates one SSH bookmark per server that connects through a jump host and runs a command on it.
  - Names starting with `isvps`, `irvps` or `euvps` use `sudo ssh3 <server>`.
  - All other names use `sudo ssh2 <server>`.
- Assigns each bookmark a colour from a 12-colour palette, in rotation.
- Writes the result to `My_Servers_pourabbas.mxtsessions`.

### Configuration

Variables at the top of the script:

| Variable | Description |
|----------|-------------|
| `IP` | Jump host address |
| `PORT` | Jump host SSH port |
| `USER` | SSH username |
| `FOLDER_NAME` | Bookmark folder name inside MobaXterm |
| `input_file` | Server list file (default `servers.txt`) |
| `output_file` | Generated session file |

### Usage

```bash
printf '%s\n' lh100 wh200 isvps10 > servers.txt
chmod +x mobaxterm_sessions_gen.sh
./mobaxterm_sessions_gen.sh
```

Then in MobaXterm: **Sessions → Import sessions** and select the generated file.

### Notes

- `sed -i` rewrites `servers.txt` in place to strip Windows line endings.
- Requires GNU `sed` and `xargs`; run it in Linux, WSL or Git Bash.
