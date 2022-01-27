package authify;

import java.io.IOException;
import java.util.Scanner;

public class Main {

    static void watermark() {
        try {
            Runtime.getRuntime().exec("cls");

            System.out.println("--> Authify Example <--");
        }
        catch(Exception e){}
    }

    static api auth_instance = new api("program version", "program key", "program api/encryption key");
    public static void main(String[] args) throws Exception {
        String user, email, pass, token;

        auth_instance.init();

        watermark();
        System.out.println("write your option : \n1) Login\n2) Register\n3) Activate\n4) All In One");

        var scanner = new Scanner(System.in);

        int option = scanner.nextInt();

        scanner.nextLine();

        switch(option){
            case 1:
                watermark();

                System.out.println("write your username : ");
                user = scanner.nextLine();

                watermark();

                System.out.println("now write your password : ");
                pass = scanner.nextLine();

                watermark();

                if(auth_instance.login(user, pass)){
                    var user_data = auth_instance.user_data;

                    System.out.println("logged in successfully !!!");

                    System.out.println(user_data.username);
                    System.out.println(user_data.email);
                    System.out.println(user_data.expires);
                    System.out.println(user_data.var);
                    System.out.println(user_data.rank);
                }
                else{
                    System.out.println(":ddd !!!");
                }
                break;

            case 2:
                watermark();

                System.out.println("write your username : ");
                user = scanner.nextLine();

                watermark();

                System.out.println("now write your email : ");
                email = scanner.nextLine();

                watermark();

                System.out.println("write your pass : ");
                pass = scanner.nextLine();

                watermark();

                System.out.println("now your token!! : ");
                token = scanner.nextLine();

                watermark();

                if(auth_instance.register(user, email, pass, token))
                    System.out.println("registered successfully!!");
                else
                    System.out.println(":(((");
                break;

            case 3:
                watermark();

                System.out.println("write your username : ");
                user = scanner.nextLine();

                watermark();

                System.out.println("now, write your token : ");
                token = scanner.nextLine();

                watermark();

                if(auth_instance.activate(user, token))
                    System.out.println("activated successfully!!");
                else
                    System.out.println(":(((");
                break;

            case 4:
                watermark();

                System.out.println("write your token : ");
                token = scanner.nextLine();

                if(auth_instance.all_in_one(token)){
                    var user_data = auth_instance.user_data;

                    System.out.println("logged in successfully !!!");

                    System.out.println(user_data.username);
                    System.out.println(user_data.email);
                    System.out.println(user_data.expires);
                    System.out.println(user_data.var);
                    System.out.println(user_data.rank);
                }
                else{
                    System.out.println(":ddd !!!");
                }
                break;

            default:
                watermark();

                System.out.println("not available option");
                break;
        }
        System.in.read();
    }
}
