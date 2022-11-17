package pku.jvd.deseri.core.switcher.stmt;

import lombok.Getter;
import lombok.Setter;
import pku.jvd.deseri.core.container.DataContainer;
import pku.jvd.deseri.core.data.Context;
import pku.jvd.deseri.core.switcher.value.ValueSwitcher;
import pku.jvd.deseri.dal.caching.bean.ref.MethodReference;
import soot.jimple.AbstractStmtSwitch;

@Getter
@Setter
public abstract class StmtSwitcher extends AbstractStmtSwitch {

    public Context context;
    public DataContainer dataContainer;
    public MethodReference methodRef;
    public ValueSwitcher leftValueSwitcher;
    public ValueSwitcher rightValueSwitcher;
    public boolean reset = true;
}
