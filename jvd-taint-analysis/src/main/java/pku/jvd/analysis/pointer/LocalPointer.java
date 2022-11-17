package pku.jvd.analysis.pointer;

import org.apache.commons.lang3.builder.HashCodeBuilder;

import soot.Local;
import soot.Type;

public class LocalPointer extends Pointer{

    Local local;

    public LocalPointer(Local local){
        this.local = local;
    }

    @Override
    public String toString(){
        return local.getName();
    }

    @Override
    public int hashCode() {
        HashCodeBuilder hcb = new HashCodeBuilder(15,17);
        hcb.append(local);
        return hcb.toHashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if(obj instanceof LocalPointer){
            return this.local.equals(((LocalPointer)obj).local);
        }
        else{
            return false;
        }
    }

    public Type getType(){
        return this.local.getType();
    }
}
