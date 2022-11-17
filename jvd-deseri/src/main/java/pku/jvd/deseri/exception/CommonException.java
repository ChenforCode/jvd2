package pku.jvd.deseri.exception;

import lombok.Getter;

@Getter
public class CommonException extends RuntimeException{
    private String msg;
    public CommonException(String msg) {
        this.msg = msg;
    }
}
