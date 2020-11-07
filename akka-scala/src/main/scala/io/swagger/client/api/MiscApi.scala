/**
 * BMK
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * OpenAPI spec version: 1.0
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */
package io.swagger.client.api

import io.swagger.client.model.LoginRequest
import io.swagger.client.model.SignUpRequest
import io.swagger.client.model.ValidateOtpRequest
import io.swagger.client.model.VerifyUniqueDetailsRequest
import io.swagger.client.core._
import io.swagger.client.core.CollectionFormats._
import io.swagger.client.core.ApiKeyLocations._

object MiscApi {

  /**
   * 
   * 
   * Expected answers:
   *   code 200 :  
   * 
   * @param userId 
   */
  def getDeviceId(userId: Int): ApiRequest[Unit] =
    ApiRequest[Unit](ApiMethods.GET, "https://bmkauth.herokuapp.com/api/v1/user", "/deviceId", "application/json")
      .withQueryParam("userId", userId)
      .withSuccessResponse[Unit](200)
        /**
   * 
   * 
   * Expected answers:
   *   code 200 :  
   * 
   * @param token 
   */
  def getUserInfo(token: String): ApiRequest[Unit] =
    ApiRequest[Unit](ApiMethods.GET, "https://bmkauth.herokuapp.com/api/v1/user", "/details", "application/json")
      .withHeaderParam("token", token)
      .withSuccessResponse[Unit](200)
        /**
   * accessible by superusers
   * 
   * Expected answers:
   *   code 200 :  
   * 
   * @param token 
   */
  def getallusers(token: String): ApiRequest[Unit] =
    ApiRequest[Unit](ApiMethods.GET, "https://bmkauth.herokuapp.com/api/v1/user", "/all", "application/json")
      .withHeaderParam("token", token)
      .withSuccessResponse[Unit](200)
        /**
   * 
   * 
   * Expected answers:
   *   code 200 :  
   * 
   * @param body 
   */
  def login(body: LoginRequest): ApiRequest[Unit] =
    ApiRequest[Unit](ApiMethods.POST, "https://bmkauth.herokuapp.com/api/v1/user", "/singin", "application/json")
      .withBody(body)
      .withSuccessResponse[Unit](200)
        /**
   * 
   * 
   * Expected answers:
   *   code 200 :  
   * 
   * @param token 
   * @param body 
   */
  def signUp(token: String, body: SignUpRequest): ApiRequest[Unit] =
    ApiRequest[Unit](ApiMethods.POST, "https://bmkauth.herokuapp.com/api/v1/user", "/signup", "application/json")
      .withBody(body)
      .withHeaderParam("token", token)
      .withSuccessResponse[Unit](200)
        /**
   * 
   * 
   * Expected answers:
   *   code 200 :  
   * 
   * @param token 
   * @param body 
   */
  def validateOtp(token: String, body: ValidateOtpRequest): ApiRequest[Unit] =
    ApiRequest[Unit](ApiMethods.PUT, "https://bmkauth.herokuapp.com/api/v1/user", "/validateOtp", "application/json")
      .withBody(body)
      .withHeaderParam("token", token)
      .withSuccessResponse[Unit](200)
        /**
   * 
   * 
   * Expected answers:
   *   code 200 :  
   * 
   * @param body 
   */
  def verifyUniqueDetails(body: VerifyUniqueDetailsRequest): ApiRequest[Unit] =
    ApiRequest[Unit](ApiMethods.POST, "https://bmkauth.herokuapp.com/api/v1/user", "/verifyUniqueDetails", "application/json")
      .withBody(body)
      .withSuccessResponse[Unit](200)
      

}

