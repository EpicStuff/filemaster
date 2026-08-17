# Storage Scope

Storage Scope is an optional, profile-based feature for keeping an app's files
separate from the user's normal files.

## Core behaviour

When Storage Scope is on for a profile, every file location the app tries to
access is handled through that profile's scope. This applies equally to home,
temporary locations, and absolute paths elsewhere on the system. There is no
special case for `~`.

The app sees and can use:

* files it previously created in that profile's private storage;
* files and folders that are deliberately excluded from the scope, subject to
  the profile's ordinary Filemaster rules.

It does not see the user's existing files merely because they are at a familiar
path. New files the app creates belong to the profile's private storage rather
than appearing in the user's normal folders.

Excluding a file or folder from the scope does not grant access to it. It only
returns that location to the normal Filemaster rules, which then allow, block,
or otherwise handle the access as usual.

## Launch behaviour

Storage Scope is either on or off for a profile; there is no per-launch choice.
When it is on, normal launches of the app use the scope automatically. If the
scope cannot be applied, the launch fails rather than starting the app without
it.

Turning Storage Scope on for an app that is already running requires that app
to be restarted.

## Data lifecycle

An app starts with clean private storage when Storage Scope is first enabled.
Its private files persist while the scope remains enabled. Turning Storage Scope
off does not merge those files into the user's normal folders. Filemaster shows
when a profile is scoped and lets the user reset its private storage explicitly.

## Profile identity

A Storage Scope belongs to a profile. Apps represented by the same profile use
the same scope, ordinary rules, and private files. Normal app updates retain the
same profile and therefore retain its scope.
