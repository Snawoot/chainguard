#!/bin/sh

[ -f ~/.config/chainguard_news_posted ] || {
	>&2 echo "File with lastrun date not found!"
	exit 3
}
last_run="$(date -Iseconds -r ~/.config/chainguard_news_posted)"
touch ~/.config/chainguard_news_posted

tmpfile="$(mktemp)"
/opt/chainguard/bin/chainguard-news ~/.config/chainguard.db "$last_run" > "$tmpfile"
[ -s "$tmpfile" ] && mail -s "chainguard news" -- vladislav@vm-0.com < "$tmpfile"
rm "$tmpfile"
