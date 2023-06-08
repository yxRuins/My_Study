## 常用包
***

1. jwt（JSON Web Token）

  - 安装相关依赖

  ```golang
  go get github.com/dgrijalva/jwt-go
  ```

  - 编写jwt工具包，用户创建和检查token 分为几个部分：

    - 指定加密密钥

    ```golang
    // 自定义密钥
    secret = []byte("16849841325189456f487")
    ```

    - 指定被保存在token中的实体对象，Claims 结构体。需要内嵌jwt.StandardClaims。这个结构体是用来保存信息的。

    ```golang
      //Claim是一些实体（通常指的用户）的状态和额外的元数据
      type Claims struct{
        Username string `json:"username"`
        Password string `json:"password"`
        jwt.StandardClaims
      }
    ```

    - 根据数据产生token：根据传入的信息，组装成一个Claims结构体对象，再从对象中获取token

    ```golang
    // 根据用户的用户名和密码产生token
    func GenerateToken(username ,password string)(string,error){
      // 设置token有效时间
      expireTime:=time.Now().Add(3*time.Hour)
      claims:=Claims{
 	    Username:       username,
        Password:       password,
        StandardClaims: jwt.StandardClaims{
        // 过期时间
  	    ExpiresAt:expireTime.Unix(),
 	      // 指定token发行人
        Issuer:"gin-blog",
       },
    }
    
      tokenClaims:=jwt.NewWithClaims(jwt.SigningMethodHS256,claims)
      //该方法内部生成签名字符串，再用于获取完整、已签名的token
      token,err:=tokenClaims.SignedString(jwtSecret)
      return token,err
    }
    ```

    - 根据token解析数据：解析出token所对应的interface{}，再使用断言解析出Claims对象，取数据

    ```golang
    // 根据传入的token值获取到Claims对象信息，（进而获取其中的用户名和密码）
    func ParseToken(token string)(*Claims,error){
      //用于解析鉴权的声明，方法内部主要是具体的解码和校验的过程，最终返回*Token
      tokenClaims, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
       return jwtSecret, nil
      })
    
      if tokenClaims!=nil{
      // 从tokenClaims中获取到Claims对象，并使用断言，将该对象转换为我们自己定义的Claims
  	  // 要传入指针，项目中结构体都是用指针传递，节省空间。
    	  if claims,ok:=tokenClaims.Claims.(*Claims);ok&&tokenClaims.Valid{
    		  return claims,nil
    	  }
      }
      return nil,err
    
    }
    ```

 - 编写路由，返回token  

   - 用户参数校验

     ```golang
      type auth struct{
       Username string `valid:"Required;MaxSize(50)"`
       Password string `valid:"Required;MaxSize(50)"`
      }
     
     func GetAuth(c *gin.Context){
       username:=c.Query("username")
       password:=c.Query("password")
     
       valid:=validation.Validation{}
        a:=auth{
     	  Username: username,
     	  Password: password,
       }
       
       
       // 与之前的对每一个数据分开验证不同，此处在auth对象中通过定义标签valid
       // 一次性校验对象中的所有字段信息
       ok,_:=valid.Valid(&a)
     
       //创建返回信息
       data:=make(map[string]interface{})
       code:=e.INVALID_PARAMS
       /*
       根据用户名密码获取token 判断流程：
       1. 先判断用户名密码是否存在
       */
       if ok{
     	  isExist:=models.CheckAuth(username,password)
     	  if isExist{
     		 token,err:=util.GenerateToken(username,password)
     		 if err!=nil{
     		  code=e.ERROR_AUTH_TOKEN
     		 }else{
     		  data["token"]=token
     			code=e.SUCCESS
     		 }
     	   }else{
     		  code=e.ERROR_AUTH
     	   }
        }else{
     	    //如果数据验证失败，则打印结果
     	    for _,err:=range valid.Errors{
     		    log.Println(err.Key,err.Message)
     	   }
       } 
     
       c.JSON(http.StatusOK,util.ReturnData(code,e.GetMsg(code),data))
      }
     ```

   - 编写中间件，校验token字符串

    ```golang
     func JWY()gin.HandlerFunc{
   	  return func(c *gin.Context){
   		 var  code int
   		 var data interface{}
   
   		 code=e.SUCCESS
   		 token:=c.Query("token")
   		 if token==""{
   			 code=e.ERROR_AUTH_NO_TOKRN
   		 }else{
   			 claims,err:=util.ParseToken(token)
   			 if err!=nil{
   				 code=e.ERROR_AUTH_CHECK_TOKEN_FAIL
   			 }else if time.Now().Unix()>claims.ExpiresAt{
   				 code=e.ERROR_AUTH_CHECK_TOKEN_TIMEOUT
   			 }
   		 }
   
   		 //如果token验证不通过，直接终止程序，c.Abort()
   		 if code!=e.SUCCESS{
   			 // 返回错误信息
   			 c.JSON(http.StatusUnauthorized,util.ReturnData(code,e.GetMsg(code),data))
   			 //终止程序
   			 c.Abort()
   		  return
   	  }
   	  c.Next()
	    }
    }
    ```
