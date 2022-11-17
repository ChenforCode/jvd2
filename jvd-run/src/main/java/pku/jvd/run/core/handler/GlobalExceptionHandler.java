package pku.jvd.run.core.handler;

import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import pku.jvd.deseri.exception.CommonException;
import pku.jvd.deseri.exception.JDKVersionErrorException;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Log log = LogFactory.get(GlobalExceptionHandler.class);
    @ExceptionHandler(value = JDKVersionErrorException.class)
    public String JDKVersionErrorException(JDKVersionErrorException e) {
        String msg = "请使用jdk1.8版本";
        log.error(msg);
        return msg;
    }

    @ExceptionHandler(value = CommonException.class)
    public String CommonException(CommonException e) {
        System.out.println("拦截到了");
        log.error(e.getMsg());
        return e.getMsg();
    }

    @ExceptionHandler(value = Exception.class)
    public String exception(Exception e) {
        log.error(e.getMessage());
        return e.getMessage();
    }
}
