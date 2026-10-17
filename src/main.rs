use tcdd::app::App;

fn main() {
    let mut app = App::new();

    println!("TCDD — Terminal Communication and Data Device");
    println!("Inicializando...");

    if app.is_running() {
        println!("Aplicação em execução.");

        if let Some(session) = app.session() {
            println!("Sessão: {:?}", session.state());
        }
    }

    match app.quit() {
        Ok(()) => println!("Aplicação encerrada."),
        Err(error) => eprintln!("Erro ao encerrar: {error:?}"),
    }
}
