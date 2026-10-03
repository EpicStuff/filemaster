# Fanotify extension in a custom kernel

The idea is to take the current fanotify notifications for delete and stuff and make it like the current fannotify open prompts.

How this will be delivered/deployed has not been decided yet.

## Outcome of the feasibility check (2026-08-27)

1. **The waiting works** but a fail-closed mode would have to be
   built, not inherited.
2. **The event cannot carry enough information.** a new event type and format
   would have to be designed.

The appeal of this option was that most of it already existed in the kernel.
What is actually reusable is the wait, and part of the queue. New structural
event types, a combined two-path format, response matching, mark rules,
fail-closed teardown, and the cross-pass verdict all remain to be written — in a
subsystem the working product already depends on.

**Correction — there is more prior work than I first said.** I originally wrote
that there was nothing to adopt and that the earlier attempts stopped before the
hard part. That was wrong, and I have since fetched and read the code.

The fanotify maintainer has a 24-patch branch from 2023 that builds most of this
option: a purpose-built new fanotify mode whose whole reason for existing is to
ask userspace **before** the kernel takes its locks, covering create, delete,
rmdir and move — including move's two directories, which is the case I wrongly
said nobody had reached. It is unmerged, unmaintained, and written against a
2023 kernel.

**But it asks the wrong question for a security product.** It asks about a
*folder plus a filename*, before the kernel has worked out which file that name
points at. The file is identified only afterwards. So an app can ask to delete
`junk.txt`, get your approval, and then — from a second thread — move a valuable
file onto that name before the deletion happens. Your "yes" gets spent on the
wrong file. I checked whether the branch's synchronisation prevents this; it does
not, and its own commit message says so outright.

Our own proof does not have this problem. It re-checks the file after the answer,
and we measured exactly this attack failing safely. That is worth keeping.

The branch also states plainly that it does not see changes made through
overlayfs, does not cover every way a file can be moved or deleted, and
deliberately skips events in one case so the listener can do its own file
operations. All of that is fine for its intended users — backup and
storage-management tools that cooperate rather than attack — and none of it is
acceptable for blocking a malicious app.

**The useful idea is separable from fanotify.** Asking before the locks is a
change to the kernel's file layer, not to fanotify. Filemaster could ask at that
earlier point and keep everything else as planned. There is probably a better
design than either: ask early, then double-check the file after the answer and
refuse if it changed. That would be cheaper than our current proof and still
safe. It has not been designed or costed.

**Correction — this option is back on the table.** I first said it did not
change the cost, because the daemon conversation, the queue and the waiting
would be the same either way. That was wrong. It is true if we keep our own
kernel module and only borrow the idea of asking earlier. It is **not** true if
we let fanotify be the thing that talks to Filemaster — because then fanotify
provides the queue, the waiting, the reply handling *and* the folder-watching
marks, all of which we were otherwise going to write.

Checking that against our own sizing: roughly a third of the kernel module we
planned to write is work fanotify already does. A saving of a quarter to two
fifths is credible.

**But the security gap is still real and still ours to fix**, along with making
it fail safely when Filemaster dies, handling a move as one decision instead of
two, covering overlayfs, and accepting that we would be modifying the code that
already runs your working Open prompts — so a mistake there breaks something
that currently works.

**There is now a number (2026-08-30): roughly 2,100–3,700 lines and
225–380 million tokens.** I had refused to give one, saying the honest way was
to port the patch first. You overruled that, correctly — every other figure in
the cost table is an estimate too.

**And the number says something worth knowing.** The saving is real but much
smaller than it looked, because it applies to the kernel module and the module
is only about two thirds of the job. On the whole option it is about **15%** of
the lines. Then the things that are harder here — dragging a 2023 patch set
forward five kernel versions, re-testing your working Open prompts every time we
touch the code underneath them, and solving the security hole the prototype
leaves open — put most of that back. On tokens the two routes come out
**level**: 225–380 million here against 234–350 million for the LSM route.

**So cost does not decide this one.** What separates them is where the risk
sits: the LSM route adds new code next to something that works, this route edits
the thing that works. Porting the patch and recounting would still replace this
estimate with a real figure.

## What reading the code settled (2026-08-30)

I flagged one question as potentially fatal to this option: when the kernel asks
Filemaster about a *name in a folder* rather than an open file, there is no open
file to answer about — so how does the kernel know which question your answer
belongs to? **It is not fatal.** The maintainer's answer was to notice that there
is always a folder to open, and open that. The same trick works for creating,
deleting and moving, so nothing new has to be invented here. That was the
biggest unknown and it came back clean.

**Making it fail safely is also cheaper than I thought** — the two known places
where fanotify lets things through when Filemaster dies are a very small change.
But reading the code turned up a **third** place nobody had recorded: if too
many requests pile up at once, fanotify quietly allows one rather than denying
it. That has to be fixed too, and it now belongs on the feature list.

**One thing did not come back clean: moving a file.** Filemaster would ideally
ask you *once* about a move — "allow moving this file from here to there?" The
kernel can carry that as one question; nothing in it currently does, and the
maintainer's own move code deliberately asks **twice** instead, once about the
source and then, only if you allowed that, once about the destination. So a
single move prompt is possible but means going our own way rather than following
the existing work.

**That turns into a product question for you, not a kernel one:** is two prompts
for one move acceptable? If yes, this route follows the existing code. If no, it
costs more here and gains nothing over the LSM route. The feature sweep now
running should answer it.

Detail and source citations: [technical note](update-option-fanotify-extension-technical.md).
