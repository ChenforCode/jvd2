package pku.jvd.analysis.pointer;


import soot.Type;

public abstract class Pointer{

    public String valueName;

    public abstract int hashCode();

    public abstract boolean equals(Object obj);

    @Override
    public abstract String toString();

    public abstract Type getType();
}
