/* 由 tools/generate_gem5_x86_dynamic_paths.py 从 x86_64.toml 生成。 */
/* 该表属于 gem5 tracer，不包含或链接 gipsim decoder。 */
static constexpr const char *x86Cmpxchg8bPathShapes[] = {
    "CLCBCCCCCS",
    "CLCBCCCCS",
};
static constexpr const char *x86Cmpxchg8bRipPathShapes[] = {
    "CCLCBCCCCCS",
    "CCLCBCCCCS",
};
static constexpr const char *x86Cmpxchg8bLockedPathShapes[] = {
    "CCLCBCCCCCSC",
    "CCLCBCCCCSC",
};
static constexpr const char *x86Cmpxchg8bLockedRipPathShapes[] = {
    "CCCLCBCCCCCSC",
    "CCCLCBCCCCSC",
};
static constexpr const char *x86Cmpxchg16bPathShapes[] = {
    "CLCBCCCCCS",
    "CLCBCCCCS",
};
static constexpr const char *x86Cmpxchg16bRipPathShapes[] = {
    "CCLCBCCCCCS",
    "CCLCBCCCCS",
};
static constexpr const char *x86Cmpxchg16bLockedPathShapes[] = {
    "CCLCBCCCCCSC",
    "CCLCBCCCCSC",
};
static constexpr const char *x86Cmpxchg16bLockedRipPathShapes[] = {
    "CCCLCBCCCCCSC",
    "CCCLCBCCCCSC",
};
static constexpr const char *x86JmpFarPathShapes[] = {
    "CCCLLBCCCCBCBCBCCCBB",
    "CCCLLBCCCCBCCBCCCBB",
};
static constexpr const char *x86JmpFarRipPathShapes[] = {
    "CCCCLLBCCCCBCBCBCCCBB",
    "CCCCLLBCCCCBCCBCCCBB",
};
static constexpr const char *x86LldtRegPathShapes[] = {
    "CBCCCCCCCCC",
    "CBC",
};
static constexpr const char *x86LldtMemPathShapes[] = {
    "LCBCCCCCCCCC",
    "LCBC",
};
static constexpr const char *x86LldtMemRipPathShapes[] = {
    "CLCBCCCCCCCCC",
    "CLCBC",
};
static constexpr const char *x86MovSegRegPathShapes[] = {
    "CBCCBCBCCC",
    "CBCCBCCCC",
    "CBCCC",
};
static constexpr const char *x86MovSegMemPathShapes[] = {
    "LCBCCBCBCCC",
    "LCBCCBCCCC",
    "LCBCCC",
};
static constexpr const char *x86MovSegMemRipPathShapes[] = {
    "CLCBCCBCBCCC",
    "CLCBCCBCCCC",
    "CLCBCCC",
};
static constexpr const char *x86RetFarPathShapes[] = {
    "LLCCCCBCCBCBCCCB",
    "LLCCCCBCCBCCCCB",
};
