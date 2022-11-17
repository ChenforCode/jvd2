package pku.jvd.deseri.dal.caching.bean.edge;

import lombok.Getter;
import lombok.Setter;
import pku.jvd.deseri.dal.caching.converter.MethodRef2StringConverter;
import pku.jvd.deseri.dal.caching.bean.ref.MethodReference;

import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import java.util.UUID;

@Getter
@Setter
@Entity
@Table(name = "Alias")
public class Alias {

    @Id
    private String id;

    @Convert(converter = MethodRef2StringConverter.class)
    private MethodReference source;

    @Convert(converter = MethodRef2StringConverter.class)
    private MethodReference target;

    public static Alias newInstance(MethodReference source, MethodReference target){
        Alias alias = new Alias();
        alias.setId(UUID.randomUUID().toString());
        alias.setSource(source);
        alias.setTarget(target);
        return alias;
    }



}
