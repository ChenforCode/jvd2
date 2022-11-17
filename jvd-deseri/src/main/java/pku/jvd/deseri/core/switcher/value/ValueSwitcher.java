package pku.jvd.deseri.core.switcher.value;

import lombok.Getter;
import lombok.Setter;
import pku.jvd.deseri.core.container.DataContainer;
import pku.jvd.deseri.core.data.Context;
import pku.jvd.deseri.core.data.TabbyVariable;
import pku.jvd.deseri.dal.caching.bean.ref.MethodReference;
import soot.Unit;
import soot.jimple.AbstractJimpleValueSwitch;

@Getter
@Setter
public abstract class ValueSwitcher extends AbstractJimpleValueSwitch {

    public Context context;
    public DataContainer dataContainer;
    public MethodReference methodRef;
    public TabbyVariable rvar;
    public boolean unbind = false;
    public boolean reset = true;
    public Unit unit;

}
