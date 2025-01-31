# Development Guidelines

## Git Workflow

We aim to maintain a [linear](https://www.bitsnbites.eu/a-tidy-linear-git-history/) git history.
In practice, this means using **rebase** when resolving conflicts instead of merge commits, whenever possible.

We also follow the principles of [trunk-based development](https://www.atlassian.com/continuous-delivery/continuous-integration/trunk-based-development).

### Commit Message Guidelines

For detailed guidance on writing commit messages, see:
- [How to Write a Git Commit Message](https://cbea.ms/git-commit/)
- [Torvalds' Git Commit Guide](https://github.com/torvalds/subsurface-for-dirk/blob/a48494d2fbed58c751e9b7e8fbff88582f9b2d02/README#L88-L115)

The most important rules to follow are:

- Separate the commit title from its body with a blank line.
- Limit the commit title to ~50 characters (or fewer).
- Capitalize the first letter of the commit title.
- Do not end the commit title with a period.
- Use the imperative mood (e.g., "Add", "Fix", "Update", "Remove").
- Wrap lines in the commit body to ~72 characters.
- Focus on what was changed and why it was changed (not how).

You can omit the commit body if the change is obvious from the title. However, if the change is not self-evident, add a commit body explaining the reasons and context behind it.

**Example commit message:**

````
Add missing clearFWState to some firewall tests

Some tests were missing the clearFWState step, which resulted
in incorrect behavior in other tests due to the presence of
states from previous runs.
````

### Pull Request Guidelines

Pull requests titles should follow the same general style as commit messages. The PR description should:

- Provide a more detailed explanation of *what* is being changed.
- Explain *why* these changes are necessary.
- If this PR fixes an issue, link it using [issue linking](https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/linking-a-pull-request-to-an-issue).
   - If no issue exists, describe the problem that the PR solves.


### C++ Style Guide

By default, follow the [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html), with the following exceptions:

- Line length is limited to 100 characters (instead of 80).
- Curly braces are placed on a new line
- Exceptions are allowed, except in dataplane code.
- Numeric built-in types (e.g., "short", "long", etc.) are allowed.
- Use tabs set to 4 spaces for indentation (instead of 2).
- C++ source files use the `.cpp` extension instead of `.cc`.
- `#pragma once` is permitted instead of traditional include guards.
- Files and directories are named using `snake_case`.
- The order of access specifiers in a class definition is ideally:

```cpp
class Example
{
  private:
    ...

  protected:
     ...

  public:
    ...
};

```

- WIP: something else?
