/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.rub.nds.futuretrust.utils;

/**
 *
 * @author vmladenov
 */

public interface Validator {
    public void validate(); //todo ValidationException; add SsoType as Input
    public void getResult(); //change void to DSS Result
    
}
