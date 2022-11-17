package pku.jvd.deseri.dal.caching.service;

import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pku.jvd.deseri.config.GlobalConfiguration;
import pku.jvd.deseri.dal.caching.bean.ref.MethodReference;
import pku.jvd.deseri.dal.caching.repository.MethodRepository;

import java.util.List;

@Service
public class MethodRefService {
    private static final Log log = LogFactory.get(MethodRefService.class);
    @Autowired
    private MethodRepository methodRepository;

    public MethodReference getMethodRefBySignature(String signature){
        return methodRepository.findMethodReferenceBySignature(signature);
    }

    public void clearCache(){
        log.info("All methods cache cleared!");
    }

    public void save(MethodReference ref){
        methodRepository.save(ref);
    }

    public void save(Iterable<MethodReference> refs){
        methodRepository.saveAll(refs);
    }

    public void save2Csv(){
        methodRepository.save2Csv(GlobalConfiguration.METHODS_CACHE_PATH);
    }

    public List<MethodReference> loadNecessaryMethodRefs(){
        return methodRepository.findAllNecessaryMethodRefs();
    }

    public int countAll(){
        return methodRepository.countAll();
    }
}
