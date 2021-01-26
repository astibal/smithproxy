def ask_bot_filter_int(val):
    try:
        tmp = int(val)
        return True
    except ValueError:
        return False


#
# Ask question, until you get answer from the list.
# Default is the first choice, choices are case insensitive.
# If choices start with same letters, shortcut response is ambiguous and first in the choice list will be returned.
# So you want avoid ambiguous choices ;-)
#
def ask_bot(answers, question, other_choices=False, other_label='Other', other_shortcut='o', other_value_filter=None):
    norm_answers = []
    for a in answers:
        norm_answers.append(str(a).strip().lower())

    trailer = '['
    for a in answers:
        trailer += str(a)
        trailer += '/'

    if other_choices:
        trailer += other_label
        trailer += '/'

    # remove last /
    trailer = trailer[:-1]
    trailer += ']'

    ask_question = question + " " + trailer + "? "

    ret = None
    while True:
        response = input(ask_question)
        rr = response.strip().lower()

        # print("response: '" + rr + "'")

        if other_choices:
            if rr.startswith(other_shortcut) or rr.startswith(other_label.strip().lower()):

                while True:
                    response = input("   -> enter new value: ")
                    if other_value_filter:
                        if not other_value_filter(response):
                            print("   !! error: invalid value")
                            continue
                    if ask_bot(['Yes','No'], "   -> is %s correct?" % response) == "Yes":
                        return response



        i = 0
        for a in norm_answers:
            # print(a + "?" + rr)

            if a.startswith(rr):
                ret = answers[i]

                # print("ret="+a)
                break
            i += 1

        if ret:
            # print("ret="+a)
            break
    return ret
