package pku.jvd.deseri.dal.caching.service;

import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pku.jvd.deseri.config.GlobalConfiguration;
import pku.jvd.deseri.dal.caching.bean.ref.ClassReference;
import pku.jvd.deseri.dal.caching.repository.ClassRepository;

import java.util.List;


@Service
public class ClassRefService {
    private static final Log log = LogFactory.get(ClassRefService.class);
    @Autowired
    private ClassRepository classRepository;

    public ClassReference getClassRefByName(String name){
        return classRepository.findClassReferenceByName(name);
    }

    public void save(ClassReference ref){
        classRepository.save(ref);
    }

    public void save(Iterable<ClassReference> refs){
        classRepository.saveAll(refs);
    }

    public void save2Csv(){
        classRepository.save2Csv(GlobalConfiguration.CLASSES_CACHE_PATH);
    }

    public List<ClassReference> loadNecessaryClassRefs(){
        return classRepository.findAllNecessaryClassRefs();
    }

    public int countAll(){
        return classRepository.countAll();
    }

}
