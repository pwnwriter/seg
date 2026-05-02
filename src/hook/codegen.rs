// https://stackoverflow.com/questions/426230/what-is-the-ld-preload-trick
// https://www.reddit.com/r/C_Programming/comments/15djso5/ld_preload_hooking/

// uses write() instead of fprintf to avoid stdio.h type conflicts
// when hooking stdio functions like puts/printf
// https://stackoverflow.com/a/29174975

pub fn generate_log_hook(func_name: &str) -> String {
    format!(
        r#"#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>

typedef void *(*orig_{func_name}_t)(void *, void *, void *, void *, void *, void *);

void *{func_name}(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6) {{
    const char msg[] = "[seg hook] {func_name}() called\n";
    write(STDERR_FILENO, msg, sizeof(msg) - 1);

    orig_{func_name}_t orig = (orig_{func_name}_t)dlsym(RTLD_NEXT, "{func_name}");
    if (!orig) {{
        const char err[] = "[seg hook] error: could not find original {func_name}\n";
        write(STDERR_FILENO, err, sizeof(err) - 1);
        return (void *)0;
    }}

    return orig(a1, a2, a3, a4, a5, a6);
}}
"#
    )
}

pub fn generate_replace_hook(func_name: &str, replace_lib_path: &str) -> String {
    format!(
        r#"#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>

typedef void *(*func_t)(void *, void *, void *, void *, void *, void *);

static void *_seg_replace_lib = NULL;

__attribute__((constructor))
static void _seg_init(void) {{
    _seg_replace_lib = dlopen("{replace_lib_path}", RTLD_NOW);
    if (!_seg_replace_lib) {{
        const char err[] = "[seg hook] warning: failed to load replacement lib\n";
        write(STDERR_FILENO, err, sizeof(err) - 1);
    }}
}}

void *{func_name}(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6) {{
    if (_seg_replace_lib) {{
        func_t replacement = (func_t)dlsym(_seg_replace_lib, "{func_name}");
        if (replacement) {{
            const char msg[] = "[seg hook] {func_name} -> replacement\n";
            write(STDERR_FILENO, msg, sizeof(msg) - 1);
            return replacement(a1, a2, a3, a4, a5, a6);
        }}
    }}

    func_t orig = (func_t)dlsym(RTLD_NEXT, "{func_name}");
    if (!orig) {{
        const char err[] = "[seg hook] error: could not find original {func_name}\n";
        write(STDERR_FILENO, err, sizeof(err) - 1);
        return (void *)0;
    }}

    return orig(a1, a2, a3, a4, a5, a6);
}}
"#
    )
}
