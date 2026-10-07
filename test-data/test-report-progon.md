Прогон файла: progon_full.json (70 кейсов)
Итог: 62/70 PASS (88.6%)

Сводка из дашборд
Всего писем обработано:  74
Из них угроз:            32
Отправлено алертов:      32
Успешно доставлено:      32 (alert_sent = alerted, потерь нет)

Распределение по категориям:
    BENIGN:        42
    TERRORISM:     11
    ILLEGAL:       10
    TECHNOGENIC:    8
    OTHER_THREAT:   3

Проверка целостности:
    total (74) = сумма всех категорий (42+11+10+8+3)
    threats (32) = total − BENIGN (74 − 42)
    alerted (32) = число писем с action=DELIVER_AND_ALERT
    alert_sent (32) = число с forward_status=ORIGINAL_AND_ALERT_SENT
    alerted == alert_sent → ни один alert-пересыл не упал

Вывод: система работает согласованно, ни одно письмо не потеряно,
все угрозы доставлены в alert-ящик, вся обычная почта дошла до адресата.

Было 8 FAIL, где AI занесла угрозу не туда, куда хотели по данным аналитика:
1. id technogenic_05
    Тема/текст: взрывчатка в метро в час пик
    Ожидали: TECHNOGENIC, но AI занесла угрозу в TERRORISM
    Итог: FAIL (спорная ситуация, где бомба считается техногенной угрозой, но это так же считается угрозой жизням. Не думаю что это ошибка, потому что оно все равно посчитало письмо как угрозу)
2. id: illegal_04
    Тема/текст: Пожалеешь, что работаешь судьёй
    Ожидали: ILLEGAL, но AI занесла угрозу в OTHER_THREAT
    Итог: FAIL (по промпту - личная угроза без конкретного плана)
3. id: illegal_05
    Тема/текст: Найду тебя и убью
    Ожидали: ILLEGAL, но AI занесла угрозу в OTHER_THREAT
    Итог: FAIL (по промпту - личная угроза без конкретного плана, AI почему то считает что он самый умный)
4. id: other_01
    Тема/текст: Залью переписки и фото в сеть
    Ожидали: OTHER_THREAT, но AI занесла угрозу в ILLEGAL
    Итог: FAIL (по промту у нее должно выдавать другие угрозы, а не нелегалку. AI иногда начинает сама думать куда отнести угрозу, а не по промту. Не очень часто, но все же своевольничает)
5. id: other_02
    Тема/текст: Запущу вирус в водоснабжение
    Ожидали: OTHER_THREAT, но AI занесла угрозу в TECHNOGENIC
    Итог: FAIL (AI посчитала атаку на инфраструктуру водоснабжения техногенной угрозой. Своевольничество)
6. id: other_04
    Тема/текст: Отравим реку
    Ожидали: OTHER_THREAT, но AI занесла угрозу в ILLEGAL
    Итог: FAIL (AI говорит, что отравление это противоправное действие и грозит законом, она конечно права, но не идет по конкретному промту)
7.  id: other_05
    Тема/текст: Взломаем систему и выложим данные клиентов
    Ожидали: OTHER_THREAT, но AI занесла угрозу в ILLEGAL
    Итог: FAIL (тут AI права - взлом и утечка данных это киберпреступление.)
8. id: other_06
    Тема/текст: Есть биологическое оружие
    Ожидали: OTHER_THREAT, но AI занесла угрозу в TERRORISM
    Итог: FAIL (биологическое оружие подразумевает массовые жертвы, что ближе к террористической угрозе, так что AI правильно сделала)
Вывод: если смотреть по логике ИИ - она в целом права, но плохо, что не следует заданному промту.
Можно ужесточить ей рамки дозволенного как то, но особой необходимости не вижу, все угрозы она все равно определяет.

Ниже сводка результатов по полученным данных с 70 кейсов
////Терроризм (terrorism_01 … terrorism_08)////

id: terrorism_01
    Тема/текст: Завтра в 12:00 в ТЦ произойдёт взрыв
    AI: TERRORISM
    Аналитик: TERRORISM
    Conf: 0.97
    Action: DELIVER_AND_ALERT → alerts-terrorism
    Итог: PASS

id: terrorism_02
    Тема/текст: В метро заложена бомба, требуют деньги
    AI: TERRORISM
    Аналитик: TERRORISM
    Conf: 0.97
    Action: DELIVER_AND_ALERT → alerts-terrorism
    Итог: PASS

id: terrorism_03
    Тема/текст: Планируем захват школы и заложников
    AI: TERRORISM
    Аналитик: TERRORISM
    Conf: 0.98
    Action: DELIVER_AND_ALERT → alerts-terrorism
    Итог: PASS

id: terrorism_04
    Тема/текст: Призываем к насилию, объекты будут уничтожены
    AI: TERRORISM
    Аналитик: TERRORISM
    Conf: 0.92
    Action: DELIVER_AND_ALERT → alerts-terrorism
    Итог: PASS

id: terrorism_05
    Тема/текст: Скоро всё сгорит, огненная атака
    AI: TERRORISM
    Аналитик: TERRORISM
    Conf: 0.90
    Action: DELIVER_AND_ALERT → alerts-terrorism
    Итог: PASS

id: terrorism_06
    Тема/текст: в3рвём ТЦ завтра в 12:00 (обфускация)
    AI: TERRORISM
    Аналитик: TERRORISM
    Conf: 0.97
    Action: DELIVER_AND_ALERT → alerts-terrorism
    Итог: PASS

id: terrorism_07
    Тема/текст: There is a bomb in the subway (en)
    AI: TERRORISM
    Аналитик: TERRORISM
    Conf: 0.95
    Action: DELIVER_AND_ALERT → alerts-terrorism
    Итог: PASS

id: terrorism_08
    Тема/текст: Готовим массовые жертвы, требования
    AI: TERRORISM
    Аналитик: TERRORISM
    Conf: 0.98
    Action: DELIVER_AND_ALERT → alerts-terrorism
    Итог: PASS

////Техногенные (technogenic_01 … technogenic_08)////

id: technogenic_01
    Тема/текст: выброс хлора на химзаводе в 12:00
    AI: TECHNOGENIC
    Аналитик: TECHNOGENIC
    Conf: 0.95
    Action: DELIVER_AND_ALERT → alerts-technogenic
    Итог: PASS

id: technogenic_02
    Тема/текст: отключим энергосеть города
    AI: TECHNOGENIC
    Аналитик: TECHNOGENIC
    Conf: 0.93
    Action: DELIVER_AND_ALERT → alerts-technogenic
    Итог: PASS

id: technogenic_03
    Тема/текст: планируем аварию на ГЭС
    AI: TECHNOGENIC
    Аналитик: TECHNOGENIC
    Conf: 0.95
    Action: DELIVER_AND_ALERT → alerts-technogenic
    Итог: PASS

id: technogenic_04
    Тема/текст: отравим водозабор города
    AI: TECHNOGENIC
    Аналитик: TECHNOGENIC
    Conf: 0.95
    Action: DELIVER_AND_ALERT → alerts-technogenic
    Итог: PASS

id: technogenic_05
    Тема/текст: взрывчатка в метро в час пик
    AI: TERRORISM
    Аналитик: TECHNOGENIC
    Conf: 0.95
    Action: DELIVER_AND_ALERT → alerts-terrorism
    Итог: FAIL (спорно — AI логичнее, это массовые жертвы на транспорте)

id: technogenic_06
    Тема/текст: авария на промышленном объекте
    AI: TECHNOGENIC
    Аналитик: TECHNOGENIC
    Conf: 0.97
    Action: DELIVER_AND_ALERT → alerts-technogenic
    Итог: PASS

id: technogenic_07
    Тема/текст: chemical leak at the plant (en)
    AI: TECHNOGENIC
    Аналитик: TECHNOGENIC
    Conf: 0.95
    Action: DELIVER_AND_ALERT → alerts-technogenic
    Итог: PASS

id: technogenic_08
    Тема/текст: план по аварии на АЭС
    AI: TECHNOGENIC
    Аналитик: TECHNOGENIC
    Conf: 0.95
    Action: DELIVER_AND_ALERT → alerts-technogenic
    Итог: PASS

////Противоправные (illegal_01 … illegal_08)////

id: illegal_01
    Тема/текст: Найду тебя и покалечу, если не вернёшь долг
    AI: ILLEGAL
    Аналитик: ILLEGAL
    Conf: 0.95
    Action: DELIVER_AND_ALERT → alerts-illegal
    Итог: PASS

id: illegal_02
    Тема/текст: Подожгу твою машину
    AI: ILLEGAL
    Аналитик: ILLEGAL
    Conf: 0.95
    Action: DELIVER_AND_ALERT → alerts-illegal
    Итог: PASS

id: illegal_03
    Тема/текст: Похищу твоего сына
    AI: ILLEGAL
    Аналитик: ILLEGAL
    Conf: 0.95
    Action: DELIVER_AND_ALERT → alerts-illegal
    Итог: PASS

id: illegal_04
    Тема/текст: Пожалеешь, что работаешь судьёй
    AI: OTHER_THREAT
    Аналитик: ILLEGAL
    Conf: 0.86
    Action: DELIVER_AND_ALERT → alerts-other
    Итог: FAIL (по промпту — личная угроза без конкретного плана)

id: illegal_05
    Тема/текст: Найду тебя и убью
    AI: OTHER_THREAT
    Аналитик: ILLEGAL
    Conf: 0.95
    Action: DELIVER_AND_ALERT → alerts-other
    Итог: FAIL (по промпту — личная угроза без конкретного плана)

id: illegal_06
    Тема/текст: Заплатишь мне за молчание
    AI: ILLEGAL
    Аналитик: ILLEGAL
    Conf: 0.95
    Action: DELIVER_AND_ALERT → alerts-illegal
    Итог: PASS

id: illegal_07
    Тема/текст: We will hurt your family (en)
    AI: ILLEGAL
    Аналитик: ILLEGAL
    Conf: 0.95
    Action: DELIVER_AND_ALERT → alerts-illegal
    Итог: PASS

id: illegal_08
    Тема/текст: статья станет последней в твоей жизни
    AI: ILLEGAL
    Аналитик: ILLEGAL
    Conf: 0.85
    Action: DELIVER_AND_ALERT → alerts-illegal
    Итог: PASS

////Деловая переписка (benign_business_01 … benign_business_10)////

id: benign_business_01
    Тема/текст: Встреча — повестка на завтра
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.99
    Action: DELIVER
    Итог: PASS

id: benign_business_02
    Тема/текст: Отпуск согласован
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.99
    Action: DELIVER
    Итог: PASS

id: benign_business_03
    Тема/текст: Прошу оплатить счёт
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.98
    Action: DELIVER
    Итог: PASS

id: benign_business_04
    Тема/текст: Отчёт за квартал
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.98
    Action: DELIVER
    Итог: PASS

id: benign_business_05
    Тема/текст: Созвонимся завтра
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.99
    Action: DELIVER
    Итог: PASS

id: benign_business_06
    Тема/текст: Документы готовы
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.99
    Action: DELIVER
    Итог: PASS

id: benign_business_07
    Тема/текст: Правки в проект
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.99
    Action: DELIVER
    Итог: PASS

id: benign_business_08
    Тема/текст: Акт подписан
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.98
    Action: DELIVER
    Итог: PASS

id: benign_business_09
    Тема/текст: С днём рождения!
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.99
    Action: DELIVER
    Итог: PASS

id: benign_business_10
    Тема/текст: Работы в субботу не будет
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.99
    Action: DELIVER
    Итог: PASS

////Новости о прошлых событиях (benign_news_01 … benign_news_08)////

id: benign_news_01
    Тема/текст: Вчера произошёл теракт
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.95
    Action: DELIVER
    Итог: PASS

id: benign_news_02
    Тема/текст: На заводе утечка, устранена
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.97
    Action: DELIVER
    Итог: PASS

id: benign_news_03
    Тема/текст: Убийство раскрыто, задержан
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.98
    Action: DELIVER
    Итог: PASS

id: benign_news_04
    Тема/текст: Спецслужбы предотвратили теракт
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.95
    Action: DELIVER
    Итог: PASS

id: benign_news_05
    Тема/текст: На ГЭС произошла авария
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.95
    Action: DELIVER
    Итог: PASS

id: benign_news_06
    Тема/текст: Серия поджогов, расследование
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.97
    Action: DELIVER
    Итог: PASS

id: benign_news_07
    Тема/текст: Обзор: теракты, катастрофы
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.95
    Action: DELIVER
    Итог: PASS

id: benign_news_08
    Тема/текст: Угроза катастрофы миновала
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.95
    Action: DELIVER
    Итог: PASS

////Метафоры, сарказм, цитаты (benign_hard_01 … benign_hard_12)////

id: benign_hard_01
    Тема/текст: Цитата из книги: «Я убью тебя»
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.98
    Action: DELIVER
    Итог: PASS

id: benign_hard_02
    Тема/текст: В фильме показали захват заложников
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.95
    Action: DELIVER
    Итог: PASS

id: benign_hard_03
    Тема/текст: Убьёт меня в шахматах
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.97
    Action: DELIVER
    Итог: PASS

id: benign_hard_04
    Тема/текст: Fwd: пересылаю письмо с угрозой
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.95
    Action: DELIVER
    Итог: PASS

id: benign_hard_05
    Тема/текст: В договоре указано про угрозу
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.95
    Action: DELIVER
    Итог: PASS

id: benign_hard_06
    Тема/текст: На выборах действовать решительно
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.97
    Action: DELIVER
    Итог: PASS

id: benign_hard_07
    Тема/текст: Процитировали фразу про бомбу
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.95
    Action: DELIVER
    Итог: PASS

id: benign_hard_08
    Тема/текст: дедлайны как у террориста
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.98
    Action: DELIVER
    Итог: PASS

id: benign_hard_09
    Тема/текст: Уничтожу этот экзамен!
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.97
    Action: DELIVER
    Итог: PASS

id: benign_hard_10
    Тема/текст: Взорвал чат шутками
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.99
    Action: DELIVER
    Итог: PASS

id: benign_hard_11
    Тема/текст: Убью время до встречи
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.99
    Action: DELIVER
    Итог: PASS

id: benign_hard_12
    Тема/текст: Эта задача — настоящий убийца
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.95
    Action: DELIVER
    Итог: PASS

////Иные угрозы (other_01 … other_06)////

id: other_01
    Тема/текст: Залью переписки и фото в сеть
    AI: ILLEGAL
    Аналитик: OTHER_THREAT
    Conf: 0.95
    Action: DELIVER_AND_ALERT → alerts-illegal
    Итог: FAIL (AI прав — шантаж = конкретное преступление)

id: other_02
    Тема/текст: Запущу вирус в водоснабжение
    AI: TECHNOGENIC
    Аналитик: OTHER_THREAT
    Conf: 0.85
    Action: DELIVER_AND_ALERT → alerts-technogenic
    Итог: FAIL (спорно — атака на инфраструктуру)

id: other_03
    Тема/текст: Уничтожу твою репутацию
    AI: OTHER_THREAT
    Аналитик: OTHER_THREAT
    Conf: 0.92
    Action: DELIVER_AND_ALERT → alerts-other
    Итог: PASS

id: other_04
    Тема/текст: Отравим реку
    AI: ILLEGAL
    Аналитик: OTHER_THREAT
    Conf: 0.90
    Action: DELIVER_AND_ALERT → alerts-illegal
    Итог: FAIL (AI прав — отравление = конкретное преступление)

id: other_05
    Тема/текст: Взломаем систему и выложим данные
    AI: ILLEGAL
    Аналитик: OTHER_THREAT
    Conf: 0.95
    Action: DELIVER_AND_ALERT → alerts-illegal
    Итог: FAIL (AI прав — киберпреступление)

id: other_06
    Тема/текст: Есть биологическое оружие
    AI: TERRORISM
    Аналитик: OTHER_THREAT
    Conf: 0.85
    Action: DELIVER_AND_ALERT → alerts-terrorism
    Итог: FAIL (AI прав — биооружие = массовые жертвы)

////Пограничные (neutral_01 … neutral_10)////

id: neutral_01
    Тема/текст: Уничтожу экзамен — готовлюсь
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.95
    Action: DELIVER
    Итог: PASS

id: neutral_02
    Тема/текст: Задача — убийца
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.98
    Action: DELIVER
    Итог: PASS

id: neutral_03
    Тема/текст: Взорвал чат мемами
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.98
    Action: DELIVER
    Итог: PASS

id: neutral_04
    Тема/текст: Убью время до электрички
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.98
    Action: DELIVER
    Итог: PASS

id: neutral_05
    Тема/текст: Я как террорист с дедлайнами
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.98
    Action: DELIVER
    Итог: PASS

id: neutral_06
    Тема/текст: Пустое тело
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.99
    Action: DELIVER
    Итог: PASS

id: neutral_07
    Тема/текст: Письмо без тела
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.00
    Action: DELIVER
    Итог: PASS

id: neutral_08
    Тема/текст: Только вложение (пусто)
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.98
    Action: DELIVER
    Итог: PASS

id: neutral_09
    Тема/текст: HTML-письмо без угроз
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.99
    Action: DELIVER
    Итог: PASS

id: neutral_10
    Тема/текст: Hello — тестовое (en)
    AI: BENIGN
    Аналитик: BENIGN
    Conf: 0.99
    Action: DELIVER
    Итог: PASS