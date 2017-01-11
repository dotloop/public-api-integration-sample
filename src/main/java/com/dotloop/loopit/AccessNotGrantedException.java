package com.dotloop.loopit;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value= HttpStatus.FORBIDDEN)
public class AccessNotGrantedException extends RuntimeException {
}
