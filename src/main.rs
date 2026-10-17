use tcdd::app::App;

fn main() {
    let mut app = App::new();

    println!("TCDD — Terminal Communication and Data Device");
    println!("Inicializando...");

    if app.running {
        println!("Aplicação em execução.");
    }

    app.quit();

    println!("Aplicação encerrada.");
}
