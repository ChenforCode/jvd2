package pku.jvd.deseri.util;

public enum ArgumentEnum {
    IS_JDK_PROCESS("build.isJDKProcess"),
    WITH_ALL_JDK("build.withAllJDK"),
    EXCLUDE_JDK("build.excludeJDK"),
    BUILD_ENABLE("build.enable"),
    BUILD_THREADS("build.threads"),
    TARGET("build.target"),
    LIBRARIES("build.libraries"),
    IS_JDK_ONLY("build.isJDKOnly"),
    LOAD_ENABLE("load.enable"),
    CHECK_FAT_JAR("build.checkFatJar"),
    SET_PTA_ENABLE("build.pta"),
    SET_DEBUG_ENABLE("debug.details"),
    SET_METHOD_MAX_DEPTH("build.method.maxDepth"),
    SET_METHOD_MAX_BODY_COUNT("build.method.maxBodyCount"),
    SET_INNER_DEBUG_ENABLE("debug.inner.details"),
    SET_THREADS_TIMEOUT("build.thread.timeout"),
    SET_INTER_PROCEDURAL("build.interProcedural"),
    SET_ALIAS_METHOD_COUNT("build.alias.maxCount"),
    SET_ARRAYS_MAX_LENGTH("build.array.maxLength"),
    SET_OBJECT_MAX_TRIGGER_TIMES("build.object.maxTriggerTimes"),
    IS_PRIM_TYPE_NEED_TO_CREATE("build.isPrimTypeNeedToCreate"),
    IS_FULL_CALL_GRAPH_CREATE("build.isFullCallGraphCreate")
    ;

    private String name="";
    ArgumentEnum(String name){
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
